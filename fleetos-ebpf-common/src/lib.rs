// SPDX-License-Identifier: Apache-2.0

#![no_std]

use bytemuck::{Pod, Zeroable};
pub use fleetos_core::hash::IdentityFingerprint;

// --- Byte-Order Safety Newtypes ---

/// A wrapper for an IPv4 address to enforce host byte-order at compile time.
#[repr(transparent)]
#[derive(Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
pub struct HostOrderIpv4(pub u32);

impl HostOrderIpv4 {
    pub fn from_network(be: u32) -> Self {
        Self(u32::from_be(be))
    }
    pub fn to_network(self) -> u32 {
        self.0.to_be()
    }
}

/// A wrapper for a port to enforce host byte-order at compile time.
#[repr(transparent)]
#[derive(Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
pub struct HostOrderPort(pub u16);

impl HostOrderPort {
    pub fn from_network(be: u16) -> Self {
        Self(u16::from_be(be))
    }
    pub fn to_network(self) -> u16 {
        self.0.to_be()
    }
}

// --- BPF Map Structs ---

/// 40 bytes, 8-byte aligned. Used for exact policy matching.
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
pub struct EbpfPolicyKey {
    pub src_fingerprint: IdentityFingerprint, // 16 bytes
    pub dst_fingerprint: IdentityFingerprint, // 16 bytes
    pub protocol: u8,                         // 1 byte  (0 = any, 6 = TCP, 17 = UDP)
    pub _pad: [u8; 3],                        // 3 bytes (aligns to 4)
    pub dst_port: HostOrderPort,              // 2 bytes (0 = any)
    pub _pad2: [u8; 2],                       // 2 bytes (aligns to 8)
} // Total: 40 bytes

/// 32 bytes. Used for wildcard policy matching (ignores port/protocol).
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
pub struct EbpfPolicyWildcardKey {
    pub src_fingerprint: IdentityFingerprint, // 16 bytes
    pub dst_fingerprint: IdentityFingerprint, // 16 bytes
} // Total: 32 bytes

/// 16 bytes.
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
pub struct EbpfPolicyValue {
    pub sag_version: u64, // offset 0, 8 bytes
    pub decision: u8,     // offset 8, 1 byte (0 = deny, 1 = allow)
    pub _pad: [u8; 7],    // offset 9, 7 bytes
} // Total: 16 bytes

/// 40 bytes. Observability event pushed to the ring buffer.
#[repr(C)]
#[derive(Copy, Clone, Pod, Zeroable)]
pub struct FlowEvent {
    pub src_hash: IdentityFingerprint, // 16 bytes
    pub dst_hash: IdentityFingerprint, // 16 bytes
    pub port: HostOrderPort,           // 2 bytes
    pub action: u8,                    // 1 byte (0 = deny, 1 = allow)
    pub direction: u8,                 //1 byte (0 = ingress, 1 = egress)
    pub _pad: [u8; 4],                 // 4 bytes
} // Total: 40 bytes

/// 12 bytes. Key for the LRU_HASH storing original destination state.
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
pub struct SockTuple {
    pub src_ip: HostOrderIpv4,   // 4 bytes
    pub dst_ip: HostOrderIpv4,   // 4 bytes
    pub src_port: HostOrderPort, // 2 bytes
    pub dst_port: HostOrderPort, // 2 bytes
} // Total: 12 bytes

// --- ER-1 REV1: Route Map Value (40 bytes, 8-byte aligned) ---
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
pub struct DummyIpRouteValue {
    pub dst_fp: IdentityFingerprint, // 16 bytes — Phase B key input
    pub target_agent_fp: IdentityFingerprint, // 16 bytes — Phase C rewrite target
    pub sag_version: u64,            //  8 bytes — purge stamp
} // Total: 40 bytes

// --- Sock State Value (32 bytes) ---
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
pub struct SockStateValue {
    pub dst_fp: IdentityFingerprint,
    pub target_agent_fp: IdentityFingerprint,
} // Total: 32 bytes

// --- ER-2 REV1: policy_stats normative enumeration ---
pub const STAT_ALLOW_HITS: u32 = 0;
pub const STAT_DENY_HITS: u32 = 1;
pub const STAT_WILDCARD_HITS: u32 = 2;
pub const STAT_DEFAULT_DENY_DROPS: u32 = 3;
pub const STAT_ROUTE_MISSES: u32 = 4;
pub const STAT_PASS_THROUGHS: u32 = 5;
pub const STAT_REWRITES: u32 = 6;
pub const STAT_RESERVED: u32 = 7;

// --- ER-4: ABI Layout Assertions ---
const _: () = assert!(core::mem::size_of::<EbpfPolicyKey>() == 40);
const _: () = assert!(core::mem::size_of::<EbpfPolicyWildcardKey>() == 32);
const _: () = assert!(core::mem::size_of::<EbpfPolicyValue>() == 16);
const _: () = assert!(core::mem::size_of::<FlowEvent>() == 40);
const _: () = assert!(core::mem::size_of::<SockTuple>() == 12);
const _: () = assert!(core::mem::size_of::<DummyIpRouteValue>() == 40);
const _: () = assert!(core::mem::size_of::<SockStateValue>() == 32);

// Alignment is 2, not 1: HostOrderPort is #[repr(transparent)] over u16.
const _: () = assert!(core::mem::align_of::<EbpfPolicyKey>() == 2);
const _: () = assert!(core::mem::align_of::<DummyIpRouteValue>() == 8);

pub const fn assert_layouts() {}
