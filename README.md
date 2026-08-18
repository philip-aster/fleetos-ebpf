# fleetos-ebpf

The kernel-level enforcement and routing plane for Fleet Orchestration System (FleetOS).

`fleetos-ebpf` provides the eBPF programs and shared C-structs that enforce FleetOS's "identity is the address" networking model directly at the kernel level. It bridges user-space workloads (Containerd containers and Cloud Hypervisor MicroVMs) and the dark overlay network by intercepting standard network traffic, mapping it to 128-bit `IdentityFingerprint` hashes, and enforcing strict, default-deny Authorization (AuthZ) policies.

## Workspace Structure

This repository is structured as a Cargo workspace to strictly separate kernel bytecode from user-space type definitions:

- **`fleetos-ebpf-common`**: A `no_std`, `no_alloc` library containing the C-structs (`EbpfPolicyKey`, `EbpfPolicyValue`, `FlowEvent`, etc.) used in BPF maps. It depends on `fleetos-core` with `default-features = false`.
- **`fleetos-ebpf`**: The actual eBPF bytecode crate. It uses the `aya-ebpf` framework and contains the BPF programs. It depends on `fleetos-ebpf-common` to ensure memory layouts match perfectly across the kernel/user-space boundary.

## eBPF Programs

This workspace contains the following eBPF programs:

- **`cgroup_sock_addr` (Containerd Path):** Intercepts `connect()` syscalls. Maps dummy IPs (e.g., `240.0.0.10`) to `IdentityFingerprint`s, stores state, and rewrites the destination to the local `fleetos-agent` loopback port.
- **`tc_cls_act` (Cloud Hypervisor Path):** A TC classifier attached to host TAP devices. Enforces Two-Tier AuthZ policy (Exact -> Wildcard -> Deny) for MicroVMs. Routes based on outer headers only to support confidential computing (SEV-SNP / TDX).
- **`sock_ops` (Same-Node Bypass):** For same-node, Container-to-Container communication. Bypasses the agent and QUIC entirely by splicing sockets directly at the kernel level via `BPF_MAP_TYPE_SOCKHASH`.
- **`FlowEvent` (Observability):** A ring buffer map that pushes flow logs (allow/deny, ingress/egress) for user-space telemetry export.

## Build & Toolchain

Because `bpfel-unknown-none` is a specialized, bare-metal target, this workspace requires the Rust nightly toolchain and the `bpf-linker` tool.

### 1. Prerequisites

```bash
# Install the nightly toolchain and Rust source code
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly

# Install the bpf-linker
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

## License

Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
