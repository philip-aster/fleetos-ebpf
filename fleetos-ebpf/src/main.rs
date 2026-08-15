#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext,
    bindings::{TC_ACT_SHOT, bpf_sock_addr},
    macros::{cgroup_sock_addr, classifier, map, sock_ops},
    maps::{HashMap, LruHashMap, RingBuf, SockHash},
    programs::{SockAddrContext, SockOpsContext, TcContext},
};

// --- Local Struct Redefinitions ---

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct IdentityFingerprint(pub [u8; 16]);

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct EbpfPolicyKey {
    pub src_fingerprint: IdentityFingerprint,
    pub dst_fingerprint: IdentityFingerprint,
    pub protocol: u8,
    pub _pad: [u8; 3],
    pub dst_port: u16,
    pub _pad2: [u8; 2],
}

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct EbpfPolicyWildcardKey {
    pub src_fingerprint: IdentityFingerprint,
    pub dst_fingerprint: IdentityFingerprint,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct EbpfPolicyValue {
    pub sag_version: u64,
    pub decision: u8,
    pub _pad: [u8; 7],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct FlowEvent {
    pub src_hash: IdentityFingerprint,
    pub dst_hash: IdentityFingerprint,
    pub port: u16,
    pub action: u8,
    pub direction: u8,
    pub _pad: [u8; 4],
}

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct SockTuple {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
}

// --- Map Definitions ---

#[map]
static DUMMY_IP_MAP: HashMap<u32, IdentityFingerprint> = HashMap::pinned(1024, 0);

#[map]
static SOCK_STATE_MAP: LruHashMap<SockTuple, IdentityFingerprint> = LruHashMap::pinned(4096, 0);

#[map]
static POLICY_EXACT: HashMap<EbpfPolicyKey, EbpfPolicyValue> = HashMap::pinned(8192, 0);

#[map]
static POLICY_WILDCARD: HashMap<EbpfPolicyWildcardKey, EbpfPolicyValue> = HashMap::pinned(4096, 0);

#[map]
static FLOW_EVENTS: RingBuf = RingBuf::pinned(256 * 4096, 0);

#[map]
static LOCAL_WORKLOADS: HashMap<IdentityFingerprint, bool> = HashMap::pinned(1024, 0);

#[map]
static SOCKHASH: SockHash<SockTuple> = SockHash::pinned(4096, 0);

// --- Program 1: cgroup_sock_addr (Containerd Path - Transparent Dialing) ---

#[cgroup_sock_addr(connect4)]
pub fn fleetos_connect4(ctx: SockAddrContext) -> i32 {
    match try_fleetos_connect4(&ctx) {
        Ok(_) => 1,
        Err(_) => 0,
    }
}

fn try_fleetos_connect4(ctx: &SockAddrContext) -> Result<(), i64> {
    // Cast the raw void pointer to the bpf_sock_addr struct
    let sa = unsafe { &mut *(ctx.as_ptr() as *mut bpf_sock_addr) };
    let dst_ip_be = sa.user_ip4;
    let dst_port = sa.user_port as u16;

    if (dst_ip_be & 0xf0000000) != 0xf0000000 {
        return Ok(()); // Not a dummy IP
    }

    let dst_fingerprint = match unsafe { DUMMY_IP_MAP.get(&dst_ip_be) } {
        Some(fp) => *fp,
        None => return Err(-1),
    };

    let tuple = SockTuple {
        src_ip: 0,
        dst_ip: dst_ip_be,
        src_port: 0,
        dst_port,
    };

    let _ = SOCK_STATE_MAP.insert(&tuple, dst_fingerprint, 0);

    sa.user_ip4 = u32::from_be_bytes([127, 0, 0, 1]);
    sa.user_port = 4242u32.to_be();

    Ok(())
}

// --- Program 2: tc_cls_act (Cloud Hypervisor Path - TAP Device) ---

#[classifier]
pub fn fleetos_tc_egress(ctx: TcContext) -> i32 {
    match try_tc_egress(&ctx) {
        Ok(_) => 0,
        Err(_) => TC_ACT_SHOT as i32,
    }
}

fn try_tc_egress(_ctx: &TcContext) -> Result<(), i64> {
    let src_fingerprint = IdentityFingerprint([0; 16]);
    let dst_fingerprint = IdentityFingerprint([0; 16]);
    let protocol: u8 = 6;
    let dst_port: u16 = 5432;

    let decision = check_policy(&src_fingerprint, &dst_fingerprint, protocol, dst_port)?;
    push_flow_event(&src_fingerprint, &dst_fingerprint, dst_port, decision, 1);

    if decision == 1 { Ok(()) } else { Err(-1) }
}

#[classifier]
pub fn fleetos_tc_ingress(ctx: TcContext) -> i32 {
    match try_tc_ingress(&ctx) {
        Ok(_) => 0,
        Err(_) => TC_ACT_SHOT as i32,
    }
}

fn try_tc_ingress(_ctx: &TcContext) -> Result<(), i64> {
    Ok(())
}

// --- Helper: Two-Tier Policy Resolution ---

fn check_policy(
    src: &IdentityFingerprint,
    dst: &IdentityFingerprint,
    protocol: u8,
    dst_port: u16,
) -> Result<u8, i64> {
    let exact_key = EbpfPolicyKey {
        src_fingerprint: *src,
        dst_fingerprint: *dst,
        protocol,
        _pad: [0; 3],
        dst_port,
        _pad2: [0; 2],
    };

    if let Some(val) = unsafe { POLICY_EXACT.get(&exact_key) } {
        return Ok(val.decision);
    }

    let wildcard_key = EbpfPolicyWildcardKey {
        src_fingerprint: *src,
        dst_fingerprint: *dst,
    };

    if let Some(val) = unsafe { POLICY_WILDCARD.get(&wildcard_key) } {
        return Ok(val.decision);
    }

    Ok(0)
}

// --- Helper: Ring Buffer Push ---

fn push_flow_event(
    src: &IdentityFingerprint,
    dst: &IdentityFingerprint,
    port: u16,
    action: u8,
    direction: u8,
) {
    let event = FlowEvent {
        src_hash: *src,
        dst_hash: *dst,
        port,
        action,
        direction,
        _pad: [0; 4],
    };

    let _ = FLOW_EVENTS.output::<FlowEvent>(&event, 0);
}

// --- Program 3: sock_ops / sockmap (Same-Node Bypass) ---

#[sock_ops]
pub fn fleetos_sockops(ctx: SockOpsContext) -> u32 {
    match try_sockops(&ctx) {
        Ok(_) => 1,
        Err(_) => 0,
    }
}

fn try_sockops(_ctx: &SockOpsContext) -> Result<(), i64> {
    let tuple = SockTuple {
        src_ip: 0,
        dst_ip: 0,
        src_port: 0,
        dst_port: 0,
    };

    let dst_fingerprint = match unsafe { SOCK_STATE_MAP.get(&tuple) } {
        Some(fp) => fp,
        None => return Err(-1),
    };

    let is_local = match unsafe { LOCAL_WORKLOADS.get(dst_fingerprint) } {
        Some(val) => *val,
        None => false,
    };

    if is_local {
        // SOCKHASH.update...
    }

    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
