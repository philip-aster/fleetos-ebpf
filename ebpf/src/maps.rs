// ebpf/src/maps.rs
// BPF Map definitions for Aya 0.2.1

use aya_ebpf::{macros::map, maps::HashMap};
use fleetos_ebpf_common::{EbpfPolicyKey, EbpfPolicyValue};

/// Hash Map populated by userland Node Agent via Watch API.
/// Maps (src_hash + dst_hash + port) -> (ALLOW / DROP action)
#[map]
pub static POLICY_MAP: HashMap<EbpfPolicyKey, EbpfPolicyValue> =
    HashMap::with_max_entries(65_536, 0); // 65,536 active authorization rules
