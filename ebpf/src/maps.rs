// ebpf/src/maps.rs
// BPF Map definitions for FleetOS eBPF kernel enforcement

use aya_ebpf::{
    macros::map,
    maps::{HashMap, RingBuf},
};
use fleetos_ebpf_common::{EbpfPolicyKey, EbpfPolicyValue};

/// Hash Map populated by userland Node Agent via Watch API.
/// Maps (src_hash + dst_hash + port) -> (ALLOW / DROP action)
#[map]
pub static POLICY_MAP: HashMap<EbpfPolicyKey, EbpfPolicyValue> =
    HashMap::with_max_entries(65_536, 0); // 65,536 active authorization rules

/// Ring Buffer for high-performance security audit events sent to userspace
#[map]
pub static AUDIT_LOG: RingBuf = RingBuf::with_byte_size(1024 * 1024, 0); // 1MB ring buffer
