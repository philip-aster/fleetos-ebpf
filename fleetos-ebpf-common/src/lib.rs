// C-compatible memory structs shared between Aya kernel code & userland fleetos-agent

#![no_std]

/// 128-bit truncated BLAKE3 identity fingerprint (16 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct IdentityHash {
    pub bytes: [u8; 16],
}

/// Key used in the `POLICY_MAP` eBPF hash table.
/// Encapsulates the Source SVID Hash, Target SVID Hash, and Target Port.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct EbpfPolicyKey {
    /// 128-bit truncated BLAKE3 fingerprint of calling workload SVID
    pub src_hash: [u8; 16],
    /// 128-bit truncated BLAKE3 fingerprint of destination workload SVID
    pub dst_hash: [u8; 16],
    /// Destination port (e.g., 5432 for Postgres)
    pub port: u16,
    /// 16-bit explicit padding for 32/64-bit alignment compliance in eBPF maps
    pub _pad: u16,
}

/// Value stored in the `POLICY_MAP` eBPF hash table.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct EbpfPolicyValue {
    /// 1 = ALLOW, 0 = DROP
    pub action: u8,
    /// Reserved space for future telemetry / rate-limiting flags
    pub _flags: u8,
    pub _pad: u16,
}

/// Network Frame Overlay Header to transit packets
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FleetosHeader {
    /// Magic identifier (0x464C = "FL")
    pub magic: u16,
    /// Protocol version (1)
    pub version: u8,
    /// Reserved flags
    pub flags: u8,
    /// Source Workload SPIFFE Hash
    pub src_hash: [u8; 16],
    /// Destination Workload SPIFFE Hash
    pub dst_hash: [u8; 16],
    /// Target Role ID (e.g., 1 = primary, 2 = replica)
    pub role_id: u16,
    /// Target Port
    pub port: u16,
}
