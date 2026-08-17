// SPDX-License-Identifier: Apache-2.0

#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext,
    bindings::{
        __sk_buff, BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB, TC_ACT_SHOT, bpf_sock_addr, bpf_sock_ops,
    },
    macros::{cgroup_sock_addr, classifier, map, sock_ops},
    maps::{HashMap, LruHashMap, RingBuf, SockHash},
    programs::{SockAddrContext, SockOpsContext, TcContext},
};
use core::mem::size_of;
use fleetos_ebpf_common::{
    EbpfPolicyKey, EbpfPolicyValue, EbpfPolicyWildcardKey, FlowEvent, HostOrderIpv4, HostOrderPort,
    IdentityFingerprint, SockTuple,
};

// --- Local Network Header Definitions ---

#[repr(C)]
struct EthHdr {
    h_dest: [u8; 6],
    h_source: [u8; 6],
    h_proto: u16,
}

#[repr(C)]
struct Ipv4Hdr {
    ihl_version: u8,
    tos: u8,
    tot_len: u16,
    id: u16,
    frag_off: u16,
    ttl: u8,
    protocol: u8,
    saddr: u32,
    daddr: u32,
}

// --- Map Definitions ---

#[map]
static DUMMY_IP_MAP: HashMap<HostOrderIpv4, IdentityFingerprint> = HashMap::pinned(1024, 0);

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
    let sa = unsafe { &mut *(ctx.as_ptr() as *mut bpf_sock_addr) };

    let dst_ip_ho = HostOrderIpv4::from_network(sa.user_ip4);
    let dst_port = HostOrderPort::from_network(sa.user_port as u16);

    // Safe to use .0 here since it's within our own type boundary
    if (dst_ip_ho.0 & 0xf0000000) != 0xf0000000 {
        return Ok(()); // Not a dummy IP
    }

    let dst_fingerprint = match unsafe { DUMMY_IP_MAP.get(&dst_ip_ho) } {
        Some(fp) => *fp,
        None => return Err(-1),
    };

    let tuple = SockTuple {
        src_ip: HostOrderIpv4::from_network(sa.msg_src_ip4),
        dst_ip: dst_ip_ho,
        src_port: HostOrderPort(0), // Source port is 0 at connect() time
        dst_port,
    };

    let _ = SOCK_STATE_MAP.insert(&tuple, dst_fingerprint, 0);

    // Rewrite destination to localhost agent
    sa.user_ip4 = 0x7f000001u32.to_be();
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

fn try_tc_egress(ctx: &TcContext) -> Result<(), i64> {
    let skb = ctx.as_ptr() as *mut __sk_buff;
    let data = unsafe { (*skb).data as usize };
    let data_end = unsafe { (*skb).data_end as usize };

    let eth_len = size_of::<EthHdr>();
    let ip_len = size_of::<Ipv4Hdr>();

    if data_end - data < eth_len + ip_len {
        return Err(-1);
    }

    let eth = unsafe { core::ptr::read_unaligned(data as *const EthHdr) };
    if eth.h_proto != (0x0800u16).to_be() {
        return Ok(()); // Not IPv4, pass through
    }

    let ip = unsafe { core::ptr::read_unaligned((data + eth_len) as *const Ipv4Hdr) };
    let src_ip_ho = HostOrderIpv4::from_network(ip.saddr);
    let dst_ip_ho = HostOrderIpv4::from_network(ip.daddr);
    let protocol = ip.protocol;

    let src_fingerprint = match unsafe { DUMMY_IP_MAP.get(&src_ip_ho) } {
        Some(fp) => *fp,
        None => IdentityFingerprint([0; 16]),
    };
    let dst_fingerprint = match unsafe { DUMMY_IP_MAP.get(&dst_ip_ho) } {
        Some(fp) => *fp,
        None => return Err(-1),
    };

    let dst_port = HostOrderPort(0); // Port parsing skipped

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
    // Ingress logic to route to fleetos-agent's user-space socket.
    // Critical Boot-Race Constraint: fleetos-agent must attach this TC classifier
    // and populate maps BEFORE the MicroVM's first packet.
    Ok(())
}

// --- Helper: Two-Tier Policy Resolution ---

fn check_policy(
    src: &IdentityFingerprint,
    dst: &IdentityFingerprint,
    protocol: u8,
    dst_port: HostOrderPort,
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

    Ok(0) // Default deny
}

// --- Helper: Ring Buffer Push ---

fn push_flow_event(
    src: &IdentityFingerprint,
    dst: &IdentityFingerprint,
    port: HostOrderPort,
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

fn try_sockops(ctx: &SockOpsContext) -> Result<(), i64> {
    let ops = unsafe { &*(ctx.as_ptr() as *mut bpf_sock_ops) };

    if ops.op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB as u32 {
        return Ok(());
    }

    let tuple = SockTuple {
        src_ip: HostOrderIpv4::from_network(ops.local_ip4),
        dst_ip: HostOrderIpv4::from_network(ops.remote_ip4),
        src_port: HostOrderPort::from_network(ops.local_port as u16),
        dst_port: HostOrderPort::from_network(ops.remote_port as u16),
    };

    let dst_fingerprint = match unsafe { SOCK_STATE_MAP.get(&tuple) } {
        Some(fp) => *fp,
        None => return Err(-1),
    };

    let is_local = match unsafe { LOCAL_WORKLOADS.get(&dst_fingerprint) } {
        Some(val) => *val,
        None => false,
    };

    if is_local {
        // let _ = SOCKHASH.update(&tuple, ops.sk as u64, 0);
    }

    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
