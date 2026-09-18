# fleetos-ebpf

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

The kernel-level enforcement and routing plane for Fleet Orchestration System (FleetOS).

`fleetos-ebpf` provides the eBPF programs and shared C-structs that enforce FleetOS's "identity is the address" networking model directly at the kernel level. It bridges user-space workloads (Containerd containers and Cloud Hypervisor MicroVMs) and the dark overlay network by intercepting standard network traffic, mapping it to 128-bit `IdentityFingerprint` hashes, and enforcing strict, default-deny Authorization (AuthZ) policies.

## Kernel Requirements

- **Production Target:** >= 5.15 LTS
- **Hard Floor:** 5.8 (required for `BPF_MAP_TYPE_RINGBUF` used by `FLOW_EVENTS`)
- **Socket Cookie Keying (v0.1.3, landed):** Uses `bpf_get_socket_cookie` in `CGROUP_SOCK_ADDR` (~5.1) and `SK_MSG` (~5.2), both below the 5.8 floor.

## Workspace Structure

This repository is structured as a Cargo workspace to strictly separate kernel bytecode from user-space type definitions:

- **`fleetos-ebpf-common`**: A `no_std`, `no_alloc` library containing the C-structs (`EbpfPolicyKey`, `EbpfPolicyValue`, `DummyIpRouteValue`, etc.) used in BPF maps. It depends on `fleetos-core` with `default-features = false`.
- **`fleetos-ebpf`**: The actual eBPF bytecode crate. It uses the `aya-ebpf` framework and contains the BPF programs. It depends on `fleetos-ebpf-common` to ensure memory layouts match perfectly across the kernel/user-space boundary.

## eBPF Programs

- **`cgroup_sock_addr`** (Containerd Path): Intercepts `connect()` syscalls. Resolves dummy IPs to destination identities, checks source identity, enforces two-tier AuthZ, and rewrites allowed connections to the local `fleetos-agent` loopback port. Sock state keyed by **socket cookie** (v0.1.3).
- **`tc_cls_act`** (Cloud Hypervisor Path): TC classifiers on host TAP devices. **Egress:** two-tier AuthZ with port-aware EXACT-tier matching (v0.1.2-rc-2) and non-first overlay fragment drops, fail-closed. **Ingress (v0.1.3, EBPF-CR-3):** boot-gated mirror of egress — overlay traffic drops until the agent arms `BOOT_GATE`, then fails closed through the same resolution chain.
- **`sock_ops`** (Same-Node Bypass): Keys `SOCK_STATE_MAP` and `SOCKHASH` by socket cookie (v0.1.3). Publishes local-destined established sockets for zero-copy splicing.
- **`sk_msg`** (Splice Redirect, v0.1.3): Redirects send-path traffic across same-node socket pairs via `SOCK_PEER_MAP` → `SOCKHASH`. Dormant until the M1 pairing mechanism lands. Attach alongside `SOCKHASH`.
- **`FlowEvent`** (Observability): A ring buffer map that pushes flow logs (allow/deny, ingress/egress) for user-space telemetry export.

## BPF Map Contracts (v0.1.3 REV2)

The agent (`fleetos-agent`) is responsible for creating, sizing, and populating these maps before attaching the programs.

| Map Name | Type | Key | Value | Purpose |
|---|---|---|---|---|
| `DUMMY_IP_ROUTE_MAP` | `HASH` (262144) | `HostOrderIpv4` | `DummyIpRouteValue` (40B) | Phase A: Dummy IP to destination/target-agent fingerprint resolution. |
| `SRC_IDENTITY_MAP` | `HASH` (1024) | `HostOrderIpv4` | `IdentityFingerprint` (16B) | Phase B: Source IP to workload identity resolution. |
| `POD_NET_COUNTERS` | `PERCPU_HASH` (4096) | `HostOrderIpv4` | `PodNetCounters` (32B) | Cumulative per-pod tx/rx byte/packet counters for autoscaling. Agent pre-populates, reads, diffs, reports rates. |
| `POLICY_EXACT` | `HASH` (8192) | `EbpfPolicyKey` (40B) | `EbpfPolicyValue` (16B) | Port/protocol-specific AuthZ rules. |
| `POLICY_WILDCARD` | `HASH` (4096) | `EbpfPolicyWildcardKey` (32B)| `EbpfPolicyValue` (16B) | Port-agnostic AuthZ rules. |
| `POLICY_STATS` | `ARRAY` (8) | `u32` | `u64` | Datapath counters (Allow, Deny, Rewrites, etc.). |
| `LOCAL_WORKLOADS` | `HASH` (1024) | `IdentityFingerprint` | `bool` | Registry of local workloads for same-node bypass. |
| `SOCK_STATE_MAP` | `LRU_HASH` (4096) | `SocketCookie` (8B) | `SockStateValue` (32B) | Phase A resolution, keyed by socket cookie. |
| `SOCKHASH` | `SOCKHASH` (4096) | `SocketCookie` (8B) | `u64` (sk) | Same-node splice endpoints. |
| `SOCK_PEER_MAP` | `HASH` (4096) | `SocketCookie` | `SocketCookie` | Sender→peer cookie pairing. Dormant until the M1 joint spec with `fleetos-agent`. |
| `BOOT_GATE` | `ARRAY` (1) | `u32` (0) | `u32` | Ingress boot gate. Agent arms after map population, before guest NIC up. |
| `FLOW_EVENTS` | `RINGBUF` (1MB) | - | `FlowEvent` (40B) | Telemetry ring buffer. |

*Note: Policy maps (`POLICY_EXACT`, `POLICY_WILDCARD`) MUST remain plain `HASH`. `LRU_HASH` is strictly prohibited for policy maps, as silent eviction of an Allow rule is an availability bug.*

## Build & Toolchain

Because `bpfel-unknown-none` is a specialized, bare-metal target, this workspace requires the Rust nightly toolchain.

### 1. Prerequisites

```bash
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly
cargo install bpf-linker
```

### 2. Compilation

To compile the eBPF bytecode, run the following from the workspace root:

```bash
cargo +nightly build --release --target bpfel-unknown-none -p fleetos-ebpf -Z build-std=core
```

### 3. Verification

To verify the compiled bytecode:

```bash
file target/bpfel-unknown-none/release/fleetos-ebpf
# Expected output: ELF 64-bit LSB relocatable, eBPF, version 1 (SYSV), not stripped
```

## Design Constraints

- **No Panics:** The BPF verifier rejects them. All programs use bounded loops, check array bounds, and return `TC_ACT_SHOT` on error.
- **No Allocations:** All maps must be pre-allocated by the user-space agent at load time.
- **Verifier-Safe:** Complex logic is deferred to user-space; kernel programs are strictly fast, linear map lookups.
- **Zero Side Effects:** `fleetos-ebpf-common` pulls in only `hash`, `time`, and `version` from `fleetos-core`, ensuring no `alloc` or `std` bloat in the bytecode.
- **Byte-Order Newtypes:** All network data in map keys uses `HostOrderIpv4` / `HostOrderPort`. Raw integers for network data are a blocking defect.

## License

Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
