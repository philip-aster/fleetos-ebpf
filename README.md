# fleetos-ebpf

The kernel-level enforcement and routing plane for FleetOS. 

This workspace contains the eBPF bytecode and shared C-structs responsible for transparent workload dialing, default-deny Authorization (AuthZ) enforcement, and same-node socket bypass. It bridges the gap between user-space workloads (Containerd containers and Cloud Hypervisor MicroVMs) and the FleetOS dark overlay network.

## Architecture Overview

In FleetOS, **identity is the address**. Workloads dial dummy IPs (e.g., `240.0.0.10`) that map to SPIFFE URIs. The eBPF programs intercept these dialing attempts, enforce AuthZ policies based on 128-bit `IdentityFingerprint` hashes, and transparently redirect the raw traffic to the local `fleetos-agent` user-space socket. The agent then wraps this traffic in QUIC and routes it over the dark overlay.

### Workspace Structure

This repository is divided into two crates to strictly separate kernel bytecode from user-space type definitions:

1. **`fleetos-ebpf-common`**: A `no_std`, `no_alloc` library. It defines the C-structs (`EbpfPolicyKey`, `EbpfPolicyValue`, `FlowEvent`, etc.) used in BPF maps. It depends on `fleetos-core` with `default-features = false`.
2. **`fleetos-ebpf`**: The actual eBPF bytecode crate. It uses `aya-ebpf` and contains the BPF programs. It depends on `fleetos-ebpf-common` to ensure memory layouts match perfectly.

## eBPF Programs

| Program | Attach Point | Description |
| :--- | :--- | :--- |
| `cgroup_sock_addr` | `connect4` / `connect6` | Intercepts Containerd workload dialing. Maps dummy IPs to `IdentityFingerprint`s, stores state, and rewrites destination to the local agent. |
| `tc_cls_act` | `SCHED_CLS` (TAP Device) | Intercepts Cloud Hypervisor MicroVM traffic. Enforces Two-Tier AuthZ policy (Exact -> Wildcard -> Deny). Routes based on outer headers only for confidential computing. |
| `sock_ops` | `sock_ops` / `sockmap` | For same-node, Container-to-Container communication. Bypasses the agent and QUIC entirely by splicing sockets directly at the kernel level. |
| `FlowEvent` | `RingBuf` | Observability map. Pushes flow logs (allow/deny, ingress/egress) for `fleetos-agent` to export as OpenTelemetry data. |

## Build & Toolchain

Because `bpfel-unknown-none` is a Tier 3 target, this workspace requires the Rust nightly toolchain and `bpf-linker`.

### 1. Prerequisites

```bash
# Install nightly toolchain and rust-src
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly

# Install bpf-linker
cargo install bpf-linker
```

### 2. Compilation

To compile the eBPF bytecode (run from the workspace root):

```bash
cargo +nightly build --release --target bpfel-unknown-none -p fleetos-ebpf -Z build-std=core
```

*Note: `fleetos-core` v0.1.2+ completely eliminates `alloc` from the `no_std` profile, allowing us to build strictly with `core`.*

### 3. Verification

To verify the compiled bytecode:

```bash
file target/bpfel-unknown-none/release/fleetos-ebpf
# Expected: ELF 64-bit LSB relocatable, eBPF, version 1 (SYSV), not stripped
```

## Downstream Integration Guide

### For `fleetos-agent` (The Orchestrator)
You are the user-space owner of the eBPF lifecycle. You load the programs via Aya, attach the TC classifier per-TAP-device, and populate the maps.

* **Map Population:** Use `fleetos-ebpf-common` types. `DUMMY_IP_MAP` is long-lived and populated by `fleetos-control`. `SOCK_STATE_MAP` is ephemeral and populated by the kernel. `POLICY_EXACT` and `POLICY_WILDCARD` must use plain `BPF_MAP_TYPE_HASH` (never LRU, to prevent dropping allow rules).
* **Boot-Race Constraint:** The TC classifier must be attached and maps populated *before* the MicroVM's network device is brought up guest-side.

### For `fleetos-router` & `fleetos-gateway` (The Data Plane)
You operate in the user-space hot path. While you do not load the eBPF programs, you must interoperate with their exact memory layouts.

* **Struct Layouts:** Depend on `fleetos-ebpf-common` to get the exact layout of `EbpfPolicyKey` (40 bytes) and `EbpfPolicyWildcardKey` (32 bytes). 
* **Byte-Order Safety:** All IP and Port fields in BPF map keys are wrapped in `HostOrderIpv4` and `HostOrderPort` newtypes. You must use `from_network()` when creating keys from wire-line data, and `to_network()` when passing values to syscalls.

## Design Constraints & Rules

* **No Panics:** The verifier will reject them. All programs use bounded loops, check array bounds, and return `TC_ACT_SHOT` on error.
* **No Allocations:** All maps must be pre-allocated by the agent.
* **Aya Framework:** Uses `aya-ebpf` macros. Do not use C or libbpf.
* **Pass the Verifier:** Complex logic is deferred to user-space (`fleetos-agent`); kernel programs are strictly fast, linear map lookups.

## License

Apache License, Version 2.0. See `LICENSE` for details.
```
