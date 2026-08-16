// SPDX-License-Identifier: Apache-2.0

#![no_std]

use bytemuck::{Pod, Zeroable};
// Re-export IdentityFingerprint so the eBPF bytecode crate doesn't need
// to depend on fleetos-core directly.
pub use fleetos_core::hash::IdentityFingerprint;

/// 40 bytes, 8-byte aligned. Used for exact policy matching.
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
pub struct EbpfPolicyKey {
    pub src_fingerprint: IdentityFingerprint, // 16 bytes
    pub dst_fingerprint: IdentityFingerprint, // 16 bytes
    pub protocol: u8,                         // 1 byte  (0 = any, 6 = TCP, 17 = UDP)
    pub _pad: [u8; 3],                        // 3 bytes (aligns to 4)
    pub dst_port: u16,                        // 2 bytes (0 = any)
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
/// Note: The Lead Architect's directive specified `decision` (u8) before `sag_version` (u64).
/// In standard `repr(C)`, this would cause 7 bytes of implicit padding after `decision`,
/// resulting in a 24-byte struct. By moving `sag_version` to offset 0, we achieve a clean
/// 16-byte struct that perfectly derives `Pod` and `Zeroable` without implicit padding.
#[repr(C)]
#[derive(Copy, Clone, Pod, Zeroable)]
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
    pub port: u16,                     // 2 bytes
    pub action: u8,                    // 1 byte (0 = deny, 1 = allow)
    pub direction: u8,                 // 1 byte (0 = ingress, 1 = egress)
    pub _pad: [u8; 4],                 // 4 bytes
} // Total: 40 bytes

/// 12 bytes. Key for the LRU_HASH storing original destination state.
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Pod, Zeroable)]
pub struct SockTuple {
    pub src_ip: u32,   // 4 bytes
    pub dst_ip: u32,   // 4 bytes
    pub src_port: u16, // 2 bytes
    pub dst_port: u16, // 2 bytes
} // Total: 12 bytes
