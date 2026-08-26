// SPDX-License-Identifier: Apache-2.0

#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext,
    bindings::{
        __sk_buff, BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB, TC_ACT_SHOT, bpf_sock_addr, bpf_sock_ops,
    },
    macros::{cgroup_sock_addr, classifier, map, sock_ops},
    maps::{Array, HashMap, LruHashMap, RingBuf, SockHash},
    programs::{SockAddrContext, SockOpsContext, TcContext},
};
use core::mem::size_of;
use fleetos_ebpf_common::{
    DummyIpRouteValue, EbpfPolicyKey, EbpfPolicyValue, EbpfPolicyWildcardKey, FlowEvent,
    HostOrderIpv4, HostOrderPort, IdentityFingerprint, STAT_ALLOW_HITS, STAT_DEFAULT_DENY_DROPS,
    STAT_DENY_HITS, STAT_PASS_THROUGHS, STAT_REWRITES, STAT_ROUTE_MISSES, STAT_WILDCARD_HITS,
    SockStateValue, SockTuple,
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
static DUMMY_IP_ROUTE_MAP: HashMap<HostOrderIpv4, DummyIpRouteValue> = HashMap::pinned(262144, 0);
#[map]
static SRC_IDENTITY_MAP: HashMap<HostOrderIpv4, IdentityFingerprint> = HashMap::pinned(1024, 0);
#[map]
static SOCK_STATE_MAP: LruHashMap<SockTuple, SockStateValue> = LruHashMap::pinned(4096, 0);
#[map]
static POLICY_STATS: Array<u64> = Array::pinned(8, 0);
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

#[inline(always)]
fn bump_stat(index: u32) {
    if let Some(ptr) = { POLICY_STATS.get_ptr_mut(index) } {
        unsafe { *ptr += 1 };
    }
}

fn try_fleetos_connect4(ctx: &SockAddrContext) -> Result<(), i64> {
    let sa = unsafe { &mut *(ctx.as_ptr() as *mut bpf_sock_addr) };
    let dst_ip_ho = HostOrderIpv4::from_network(sa.user_ip4);
    let dst_port = HostOrderPort::from_network(sa.user_port as u16);

    // Phase 0: Non-overlay passthrough
    if (dst_ip_ho.0 & 0xf0000000) != 0xf0000000 {
        bump_stat(STAT_PASS_THROUGHS);
        return Ok(());
    }

    // Phase A: Resolution
    let route = match unsafe { DUMMY_IP_ROUTE_MAP.get(&dst_ip_ho) } {
        Some(v) => *v,
        None => {
            bump_stat(STAT_ROUTE_MISSES);
            return Err(-1);
        }
    };

    // Source Identity (Agent populated)
    let src_ip_ho = HostOrderIpv4::from_network(sa.msg_src_ip4);
    let src_fingerprint = match unsafe { SRC_IDENTITY_MAP.get(&src_ip_ho) } {
        Some(fp) => *fp,
        None => {
            bump_stat(STAT_DEFAULT_DENY_DROPS);
            return Err(-1);
        } // Unidentifiable = deny
    };

    // Phase B: Authorization
    let decision = check_policy(&src_fingerprint, &route.dst_fp, sa.protocol as u8, dst_port)?;
    if decision == 0 {
        return Err(-1);
    }

    // Phase C: Rewrite
    bump_stat(STAT_REWRITES); // Invariant: ALLOW_HITS == REWRITES in this hook

    let tuple = SockTuple {
        src_ip: src_ip_ho,
        dst_ip: dst_ip_ho,
        src_port: HostOrderPort(0),
        dst_port,
    };
    let state = SockStateValue {
        dst_fp: route.dst_fp,
        target_agent_fp: route.target_agent_fp,
    };
    let _ = SOCK_STATE_MAP.insert(&tuple, &state, 0);

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
        return Ok(());
    }

    let ip = unsafe { core::ptr::read_unaligned((data + eth_len) as *const Ipv4Hdr) };
    let src_ip_ho = HostOrderIpv4::from_network(ip.saddr);
    let dst_ip_ho = HostOrderIpv4::from_network(ip.daddr);

    if (dst_ip_ho.0 & 0xf0000000) != 0xf0000000 {
        bump_stat(STAT_PASS_THROUGHS);
        return Ok(());
    }

    let route = match unsafe { DUMMY_IP_ROUTE_MAP.get(&dst_ip_ho) } {
        Some(v) => *v,
        None => {
            bump_stat(STAT_ROUTE_MISSES);
            return Err(-1);
        }
    };

    let src_fingerprint = match unsafe { SRC_IDENTITY_MAP.get(&src_ip_ho) } {
        Some(fp) => *fp,
        None => IdentityFingerprint([0; 16]), // Fall through to default deny
    };

    let dst_port = HostOrderPort(0);
    let decision = check_policy(&src_fingerprint, &route.dst_fp, ip.protocol, dst_port)?;
    push_flow_event(&src_fingerprint, &route.dst_fp, dst_port, decision, 1);

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
        bump_stat(if val.decision == 1 {
            STAT_ALLOW_HITS
        } else {
            STAT_DENY_HITS
        });
        return Ok(val.decision);
    }

    let wildcard_key = EbpfPolicyWildcardKey {
        src_fingerprint: *src,
        dst_fingerprint: *dst,
    };
    if let Some(val) = unsafe { POLICY_WILDCARD.get(&wildcard_key) } {
        bump_stat(STAT_WILDCARD_HITS);
        bump_stat(if val.decision == 1 {
            STAT_ALLOW_HITS
        } else {
            STAT_DENY_HITS
        });
        return Ok(val.decision);
    }

    bump_stat(STAT_DEFAULT_DENY_DROPS);
    Ok(0)
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

    let state = match unsafe { SOCK_STATE_MAP.get(&tuple) } {
        Some(v) => *v,
        None => return Err(-1),
    };

    let is_local = match unsafe { LOCAL_WORKLOADS.get(&state.dst_fp) } {
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
