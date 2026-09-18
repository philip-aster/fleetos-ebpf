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

/// Socket cookie key (EBPF-CR-1). Kernel-generated, stable for the lifetime
/// of the socket, and identical across cgroup/connect4 and sock_ops hooks for
/// the same socket — unlike any 4-tuple (the connect4 rewrite mutates the
/// destination, and the ephemeral source port is unassigned at connect time).
/// Host-native value: no byte-order concern; the newtype exists for type
/// distinctness from arbitrary u64s.
#[repr(transparent)]
#[derive(Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
pub struct SocketCookie(pub u64);

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

/// 32 bytes. Per-pod cumulative network counters (EBPF-CR-5).
/// Incremented in the TC datapath for allowed overlay traffic only.
/// Agent reads periodically, diffs consecutive reads, divides by the
/// interval, and reports per-second rates to control via PodMetrics
/// (CR-CORE-9 / CR-CTRL-8 net-metric unit contract).
///
/// Coverage: TAP/MicroVM path only. Containerd-path traffic is proxied
/// through the agent (which accounts its own bytes); the agent merges
/// both sources before reporting.
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
pub struct PodNetCounters {
    pub tx_bytes: u64,   // 8 bytes — cumulative egress bytes
    pub tx_packets: u64, // 8 bytes — cumulative egress packets
    pub rx_bytes: u64,   // 8 bytes — cumulative ingress bytes
    pub rx_packets: u64, // 8 bytes — cumulative ingress packets
} // Total: 32 bytes

// --- ER-2 REV1: policy_stats normative enumeration ---
pub const STAT_ALLOW_HITS: u32 = 0;
pub const STAT_DENY_HITS: u32 = 1;
pub const STAT_WILDCARD_HITS: u32 = 2;
pub const STAT_DEFAULT_DENY_DROPS: u32 = 3;
pub const STAT_ROUTE_MISSES: u32 = 4;
pub const STAT_PASS_THROUGHS: u32 = 5;
pub const STAT_REWRITES: u32 = 6;
// Index 7 allocated by control (telemetry alignment, per Q5 ruling):
// non-first overlay IP fragment drops, fail-closed, counted in both TC
// directions.
pub const STAT_FRAGMENT_DROPS: u32 = 7;

// --- ER-4: ABI Layout Assertions ---
const _: () = assert!(core::mem::size_of::<EbpfPolicyKey>() == 40);
const _: () = assert!(core::mem::size_of::<EbpfPolicyWildcardKey>() == 32);
const _: () = assert!(core::mem::size_of::<EbpfPolicyValue>() == 16);
const _: () = assert!(core::mem::size_of::<FlowEvent>() == 40);
const _: () = assert!(core::mem::size_of::<SocketCookie>() == 8);
const _: () = assert!(core::mem::size_of::<DummyIpRouteValue>() == 40);
const _: () = assert!(core::mem::size_of::<SockStateValue>() == 32);
const _: () = assert!(core::mem::size_of::<PodNetCounters>() == 32);
// Alignment is 2, not 1: HostOrderPort is #[repr(transparent)] over u16.
const _: () = assert!(core::mem::align_of::<EbpfPolicyKey>() == 2);
const _: () = assert!(core::mem::align_of::<DummyIpRouteValue>() == 8);

pub const fn assert_layouts() {}
