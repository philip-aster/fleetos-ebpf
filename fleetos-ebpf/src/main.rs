// SPDX-License-Identifier: Apache-2.0
//
// Kernel floor (EBPF-CR Q1 ruling, recorded per Orchestrator memo):
// production target >= 5.15 LTS. Hard floor is 5.8 (BPF_MAP_TYPE_RINGBUF
// for FLOW_EVENTS). Socket-cookie keying (EBPF-CR-1, landed in v0.1.3)
// needs bpf_get_socket_cookie in CGROUP_SOCK_ADDR (~5.1) and SK_MSG (~5.2),
// both below the floor — any kernel that loads these programs today
// already supports it.
#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext,
    bindings::{
        __sk_buff, BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB, TC_ACT_SHOT, bpf_sock_addr, bpf_sock_ops,
    },
    helpers::bpf_get_socket_cookie,
    macros::{cgroup_sock_addr, classifier, map, sk_msg, sock_ops},
    maps::{Array, HashMap, LruHashMap, PerCpuHashMap, RingBuf, SockHash},
    programs::{SkMsgContext, SockAddrContext, SockOpsContext, TcContext},
};
use core::mem::size_of;
use fleetos_ebpf_common::{
    DummyIpRouteValue, EbpfPolicyKey, EbpfPolicyValue, EbpfPolicyWildcardKey, FlowEvent,
    HostOrderIpv4, HostOrderPort, IdentityFingerprint, PodNetCounters, STAT_ALLOW_HITS,
    STAT_DEFAULT_DENY_DROPS, STAT_DENY_HITS, STAT_FRAGMENT_DROPS, STAT_PASS_THROUGHS,
    STAT_REWRITES, STAT_ROUTE_MISSES, STAT_WILDCARD_HITS, SockStateValue, SocketCookie,
};

// sk_msg verdict codes (kernel enum sk_action).
const SK_PASS: u32 = 1;

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
// EBPF-CR-1: cookie-keyed. The cookie is derivable in both connect4 and
// sock_ops for the same socket; no post-rewrite tuple ever is.
#[map]
static SOCK_STATE_MAP: LruHashMap<SocketCookie, SockStateValue> = LruHashMap::pinned(4096, 0);
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
// EBPF-CR-2: same-node splice. Keyed by cookie (coordinated with CR-1).
#[map]
static SOCKHASH: SockHash<SocketCookie> = SockHash::pinned(4096, 0);
// EBPF-CR-2: sender cookie -> peer cookie. DORMANT until the M1 pairing
// mechanism lands (joint spec with fleetos-agent); the redirect path is
// ABI-frozen and ready to fire the moment this map is populated.
#[map]
static SOCK_PEER_MAP: HashMap<SocketCookie, SocketCookie> = HashMap::pinned(4096, 0);
// EBPF-CR-3 / Q4b: one-entry boot gate. fleetos-agent arms index 0 to 1
// after populating all maps and BEFORE the guest NIC comes up. Overlay
// ingress drops until armed — the fail-closed backstop for the boot race.
#[map]
static BOOT_GATE: Array<u32> = Array::pinned(1, 0);

// EBPF-CR-5: per-pod cumulative network counters for autoscaling (CR-CTRL-8)
// and observability. PERCPU: each CPU writes its own slot — no cache-line
// contention on the packet path. Agent sums across CPUs when reading.
// Keyed by workload IP (same key space as SRC_IDENTITY_MAP).
#[map]
static POD_NET_COUNTERS: PerCpuHashMap<HostOrderIpv4, PodNetCounters> =
    PerCpuHashMap::pinned(4096, 0);

// --- Program 1: cgroup_sock_addr (Containerd Path - Transparent Dialing) ---

#[cgroup_sock_addr(connect4)]
pub fn fleetos_connect4(ctx: SockAddrContext) -> i32 {
    match try_fleetos_connect4(&ctx) {
        Ok(()) => 1,
        Err(_) => 0,
    }
}

#[inline(always)]
fn bump_stat(index: u32) {
    if let Some(ptr) = { POLICY_STATS.get_ptr_mut(index) } {
        unsafe { *ptr += 1 };
    }
}

/// EBPF-CR-5: accumulate byte/packet counters for allowed overlay traffic.
/// Egress keys on src_ip (the sending workload); ingress keys on dst_ip
/// (the receiving workload). Both match SRC_IDENTITY_MAP's key space, so
/// the agent pre-populates entries at the same time it populates identity.
///
/// Entry missing = workload IP not yet registered by the agent. Counters
/// are observability, not enforcement: skip silently (never block traffic
/// for a missing counter entry).
#[inline(always)]
fn bump_net_counters(ip: &HostOrderIpv4, tx: bool, bytes: u32) {
    if let Some(counters) = { POD_NET_COUNTERS.get_ptr_mut(ip) } {
        unsafe {
            if tx {
                (*counters).tx_bytes += bytes as u64;
                (*counters).tx_packets += 1;
            } else {
                (*counters).rx_bytes += bytes as u64;
                (*counters).rx_packets += 1;
            }
        }
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

    // Phase C: Rewrite.
    // EBPF-CR-1: sock state is keyed by socket cookie so fleetos_sockops can
    // find it after the rewrite. Cookie 0 = unavailable: skip the state store;
    // the connection degrades gracefully to the agent path. The bypass is an
    // optimization — it must never gate connectivity or enforcement.
    let cookie =
        SocketCookie(unsafe { bpf_get_socket_cookie(ctx.as_ptr() as *mut core::ffi::c_void) });
    if cookie.0 != 0 {
        let state = SockStateValue {
            dst_fp: route.dst_fp,
            target_agent_fp: route.target_agent_fp,
        };
        let _ = SOCK_STATE_MAP.insert(&cookie, &state, 0);
    }

    bump_stat(STAT_REWRITES); // Invariant: ALLOW_HITS == REWRITES in this hook
    sa.user_ip4 = 0x7f000001u32.to_be();
    sa.user_port = 4242u32.to_be();
    Ok(())
}

// --- Program 2: tc_cls_act (Cloud Hypervisor Path - TAP Device) ---

#[classifier]
pub fn fleetos_tc_egress(ctx: TcContext) -> i32 {
    match try_tc_egress(&ctx) {
        Ok(()) => 0,
        Err(_) => TC_ACT_SHOT as i32,
    }
}

/// EBPF-CR-4: transport-layer destination port. IHL gives the true IPv4
/// header length so options cannot shift the transport offset; IHL < 5 is
/// malformed → fail-closed. TCP and UDP both carry the destination port at
/// offset 2 of the transport header; other protocols stay on the wildcard
/// tier (port 0) per the CR. Truncated transport header → fail-closed.
#[inline(always)]
fn parse_dst_port(
    ip: &Ipv4Hdr,
    data: usize,
    data_end: usize,
    eth_len: usize,
) -> Result<HostOrderPort, i64> {
    let ihl = (ip.ihl_version & 0x0f) as usize;
    if ihl < 5 {
        return Err(-1);
    }
    if ip.protocol != 6 && ip.protocol != 17 {
        return Ok(HostOrderPort(0));
    }
    let port_off = eth_len + ihl * 4 + 2;
    if data_end - data < port_off + 2 {
        return Err(-1);
    }
    let port_be = unsafe { core::ptr::read_unaligned((data + port_off) as *const u16) };
    Ok(HostOrderPort::from_network(port_be))
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

    // EBPF-CR-4 / Q5 ruling: non-first overlay IP fragments carry no transport
    // header, so port-specific policy cannot be evaluated on them. Deliberate
    // fragmentation is a port-DENY bypass vector and the dark-overlay posture
    // is fail-closed: drop, counted via STAT_FRAGMENT_DROPS (index 7, allocated
    // by control). First fragments and unfragmented packets (offset == 0)
    // proceed to normal evaluation.
    let frag_off = u16::from_be(ip.frag_off);
    if (frag_off & 0x1FFF) != 0 {
        bump_stat(STAT_FRAGMENT_DROPS);
        return Err(-1);
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

    let dst_port = parse_dst_port(&ip, data, data_end, eth_len)?;
    let decision = check_policy(&src_fingerprint, &route.dst_fp, ip.protocol, dst_port)?;
    if decision == 1 {
        // EBPF-CR-5: count egress bytes for autoscaling/observability.
        // Only allowed traffic is counted — denied packets don't flow,
        // so they don't consume resources the autoscaler should react to.
        bump_net_counters(&src_ip_ho, true, unsafe { (*skb).len });
    }
    push_flow_event(&src_fingerprint, &route.dst_fp, dst_port, decision, 1);
    if decision == 1 { Ok(()) } else { Err(-1) }
}

#[classifier]
pub fn fleetos_tc_ingress(ctx: TcContext) -> i32 {
    match try_tc_ingress(&ctx) {
        Ok(()) => 0,
        Err(_) => TC_ACT_SHOT as i32,
    }
}

fn try_tc_ingress(ctx: &TcContext) -> Result<(), i64> {
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

    // Assumption A (Q4a, symmetric): non-overlay passes through untouched.
    if (dst_ip_ho.0 & 0xf0000000) != 0xf0000000 {
        bump_stat(STAT_PASS_THROUGHS);
        return Ok(());
    }

    // Boot gate: overlay ingress drops until fleetos-agent arms the gate.
    // Not counted: index 7 is allocated to fragment drops; a boot-gate
    // counter needs a fresh index (array extension) from control.
    if !matches!(BOOT_GATE.get(0), Some(&1)) {
        return Err(-1);
    }

    // Q5 symmetric: non-first overlay fragments dropped fail-closed,
    // counted via STAT_FRAGMENT_DROPS (index 7).
    let frag_off = u16::from_be(ip.frag_off);
    if (frag_off & 0x1FFF) != 0 {
        bump_stat(STAT_FRAGMENT_DROPS);
        return Err(-1);
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
        None => IdentityFingerprint([0; 16]),
    };

    let dst_port = parse_dst_port(&ip, data, data_end, eth_len)?;
    let decision = check_policy(&src_fingerprint, &route.dst_fp, ip.protocol, dst_port)?;
    if decision == 1 {
        // EBPF-CR-5: count ingress bytes for autoscaling/observability.
        // Keyed on dst_ip: the receiving workload.
        bump_net_counters(&dst_ip_ho, false, unsafe { (*skb).len });
    }
    push_flow_event(&src_fingerprint, &route.dst_fp, dst_port, decision, 0);
    if decision == 1 { Ok(()) } else { Err(-1) }
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

// --- Program 3: sock_ops (Same-Node Bypass) ---

#[sock_ops]
pub fn fleetos_sockops(ctx: SockOpsContext) -> u32 {
    match try_sockops(&ctx) {
        Ok(()) => 1,
        Err(_) => 0,
    }
}

fn try_sockops(ctx: &SockOpsContext) -> Result<(), i64> {
    let ops = unsafe { &*(ctx.as_ptr() as *mut bpf_sock_ops) };
    if ops.op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB as u32 {
        return Ok(());
    }

    // EBPF-CR-1: the cookie here is identical to the one connect4 stored —
    // same socket, stable across the connect4 -> ACTIVE_ESTABLISHED
    // transition. Post-rewrite tuples can never match; cookies always do.
    // MUST be mutable: Aya's SockHash::update requires `impl BorrowMut<K>`.
    let mut cookie =
        SocketCookie(unsafe { bpf_get_socket_cookie(ctx.as_ptr() as *mut core::ffi::c_void) });
    if cookie.0 == 0 {
        return Ok(()); // Cookie unavailable: this socket cannot be spliced
    }

    let state = match unsafe { SOCK_STATE_MAP.get(&cookie) } {
        Some(v) => *v,
        // Not a fleetos-managed connection (agent sockets, SSH, etc.) or
        // the state was evicted. Nothing to do.
        None => return Ok(()),
    };

    let is_local = match unsafe { LOCAL_WORKLOADS.get(&state.dst_fp) } {
        Some(val) => *val,
        None => false,
    };

    if is_local {
        // EBPF-CR-2: publish this endpoint for same-node splicing.
        // Explicitly cast the raw context pointer to `*mut bpf_sock_ops`
        // before taking a mutable reference to satisfy Aya's `BorrowMut` bound.
        let sk_ops = unsafe { &mut *(ctx.as_ptr() as *mut bpf_sock_ops) };
        let _ = SOCKHASH.update(&mut cookie, sk_ops, 0);
    }
    Ok(())
}

// --- Program 4: sk_msg (Same-Node Splice Redirect, EBPF-CR-2) ---
//
// Fires on the send path of sockets published in SOCKHASH. Redirect chain:
//   own cookie -> SOCK_PEER_MAP (peer cookie) -> SOCKHASH (peer socket)
//
// WATCH (verify on target kernel before activation): bpf_get_socket_cookie
// availability on BPF_PROG_TYPE_SK_MSG. If the verifier rejects it, the
// joint spec falls back to sk_storage-based peer tagging. The redirect path
// is dormant until SOCK_PEER_MAP is populated (M1 mechanism, joint spec
// with fleetos-agent), so this watch item does not block the release.

#[sk_msg]
pub fn fleetos_sk_msg(ctx: SkMsgContext) -> u32 {
    let cookie =
        SocketCookie(unsafe { bpf_get_socket_cookie(ctx.as_ptr() as *mut core::ffi::c_void) });
    if cookie.0 == 0 {
        return SK_PASS;
    }
    let mut peer = match unsafe { SOCK_PEER_MAP.get(&cookie) } {
        Some(p) => *p,
        None => return SK_PASS, // No pairing: send proceeds normally
    };
    SOCKHASH.redirect_msg(&ctx, &mut peer, 0) as u32
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
