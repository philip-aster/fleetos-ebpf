//! EBPF-CR-5 contract + semantics tests for per-pod network counters.
//!
//! Runs on the host (no kernel). Verifies:
//!   1. ABI layout of `PodNetCounters` and the map key size.
//!   2. The reference aggregate/rate logic consumers (fleetos-agent) MUST implement.
//!
//! The in-kernel increment path is covered by the gated smoketest (see
//! HANDOVER-pod-net-counters.md), which loads the compiled object.

use fleetos_ebpf_common::{HostOrderIpv4, PodNetCounters};

// ---------- 1. ABI layout ----------

#[test]
fn pod_net_counters_layout_is_frozen() {
    assert_eq!(core::mem::size_of::<PodNetCounters>(), 32);
    assert_eq!(core::mem::align_of::<PodNetCounters>(), 8);

    let c = PodNetCounters {
        tx_bytes: 0,
        tx_packets: 0,
        rx_bytes: 0,
        rx_packets: 0,
    };
    let base = &c as *const _ as usize;
    assert_eq!((&c.tx_bytes as *const _ as usize) - base, 0);
    assert_eq!((&c.tx_packets as *const _ as usize) - base, 8);
    assert_eq!((&c.rx_bytes as *const _ as usize) - base, 16);
    assert_eq!((&c.rx_packets as *const _ as usize) - base, 24);
}

#[test]
fn map_key_matches_src_identity_keyspace() {
    // POD_NET_COUNTERS is keyed by HostOrderIpv4 (4 bytes), the same key
    // space as SRC_IDENTITY_MAP, so the agent can correlate IP -> pod.
    assert_eq!(core::mem::size_of::<HostOrderIpv4>(), 4);
}

// ---------- 2. Reference aggregate + rate logic ----------
// Canonical implementation fleetos-agent must port. Kept here so the
// semantics are test-locked before the agent exists.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Agg {
    tx_bytes: u64,
    tx_packets: u64,
    rx_bytes: u64,
    rx_packets: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Rate {
    tx_bytes_per_sec: u64,
    tx_packets_per_sec: u64,
    rx_bytes_per_sec: u64,
    rx_packets_per_sec: u64,
}

/// Sum the per-CPU samples for one IP into a single aggregate.
fn aggregate(per_cpu: &[PodNetCounters]) -> Agg {
    per_cpu.iter().fold(Agg::default(), |a, c| Agg {
        tx_bytes: a.tx_bytes.saturating_add(c.tx_bytes),
        tx_packets: a.tx_packets.saturating_add(c.tx_packets),
        rx_bytes: a.rx_bytes.saturating_add(c.rx_bytes),
        rx_packets: a.rx_packets.saturating_add(c.rx_packets),
    })
}

/// Per-second rate between two aggregate samples. `None` if the interval is
/// zero. `wrapping_sub` tolerates u64 counter wraparound.
fn rate(prev: &Agg, curr: &Agg, interval_secs: u64) -> Option<Rate> {
    if interval_secs == 0 {
        return None;
    }
    Some(Rate {
        tx_bytes_per_sec: curr.tx_bytes.wrapping_sub(prev.tx_bytes) / interval_secs,
        tx_packets_per_sec: curr.tx_packets.wrapping_sub(prev.tx_packets) / interval_secs,
        rx_bytes_per_sec: curr.rx_bytes.wrapping_sub(prev.rx_bytes) / interval_secs,
        rx_packets_per_sec: curr.rx_packets.wrapping_sub(prev.rx_packets) / interval_secs,
    })
}

fn counters(tx_b: u64, tx_p: u64, rx_b: u64, rx_p: u64) -> PodNetCounters {
    PodNetCounters {
        tx_bytes: tx_b,
        tx_packets: tx_p,
        rx_bytes: rx_b,
        rx_packets: rx_p,
    }
}

#[test]
fn aggregate_sums_across_cpus() {
    let per_cpu = [
        counters(100, 1, 0, 0),
        counters(50, 2, 10, 1),
        counters(0, 0, 5, 1),
    ];
    let agg = aggregate(&per_cpu);
    assert_eq!(
        agg,
        Agg {
            tx_bytes: 150,
            tx_packets: 3,
            rx_bytes: 15,
            rx_packets: 2
        }
    );
}

#[test]
fn rate_computes_per_second() {
    let prev = aggregate(&[counters(0, 0, 0, 0)]);
    let curr = aggregate(&[counters(1000, 10, 500, 5)]);
    let r = rate(&prev, &curr, 10).unwrap();
    assert_eq!(r.tx_bytes_per_sec, 100);
    assert_eq!(r.tx_packets_per_sec, 1);
    assert_eq!(r.rx_bytes_per_sec, 50);
    assert_eq!(r.rx_packets_per_sec, 0); // 5/10 truncates to 0
}

#[test]
fn rate_zero_interval_is_none() {
    let a = aggregate(&[counters(1, 1, 1, 1)]);
    assert!(rate(&a, &a, 0).is_none());
}

#[test]
fn rate_no_change_is_zero() {
    let a = aggregate(&[counters(42, 7, 9, 3)]);
    let r = rate(&a, &a, 5).unwrap();
    assert_eq!(r.tx_bytes_per_sec, 0);
    assert_eq!(r.rx_packets_per_sec, 0);
}

#[test]
fn rate_handles_wraparound() {
    let prev = aggregate(&[counters(u64::MAX - 10, 0, 0, 0)]);
    let curr = aggregate(&[counters(5, 0, 0, 0)]); // wrapped past u64::MAX
    let r = rate(&prev, &curr, 1).unwrap();
    // (5 - (MAX-10)) mod 2^64 == 16
    assert_eq!(r.tx_bytes_per_sec, 16);
}
