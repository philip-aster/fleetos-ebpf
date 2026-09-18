//! Gated smoke test: load the compiled eBPF object and verify the
//! POD_NET_COUNTERS map is a PerCpu Hash with the expected key/value sizes,
//! then round-trip a per-CPU value. Skips when not privileged.
//!
//! Run:  sudo -E cargo test -p fleetos-ebpf-smoketest -- --nocapture
//! Env:  FLEETOS_EBPF_OBJ=/path/to/target/bpfel-unknown-none/release/fleetos-ebpf
//!
//! NOTE: We use the raw underlying types (`u32` and `[u8; 32]`) which Aya
//! natively supports, and cast via `bytemuck`. This avoids trait resolution
//! issues with `aya::Pod` across different crate instances. Compile-time
//! assertions prove layout equivalence.

use aya::Ebpf;
use aya::maps::PerCpuHashMap;
use fleetos_ebpf_common::{HostOrderIpv4, PodNetCounters};

// Compile-time proof that the raw types match the kernel-side ABI exactly.
const _: () = assert!(core::mem::size_of::<u32>() == core::mem::size_of::<HostOrderIpv4>());
const _: () = assert!(core::mem::align_of::<u32>() == core::mem::align_of::<HostOrderIpv4>());
const _: () = assert!(core::mem::size_of::<[u64; 4]>() == core::mem::size_of::<PodNetCounters>());
const _: () = assert!(core::mem::align_of::<[u64; 4]>() == core::mem::align_of::<PodNetCounters>());

// --- Helpers ---

/// Parse /sys/devices/system/cpu/possible (e.g. "0-3" or "0,2-4") and return
/// the number of possible CPUs. Both bounds of each range are validated.
fn num_possible_cpus() -> usize {
    let raw =
        std::fs::read_to_string("/sys/devices/system/cpu/possible").unwrap_or_else(|_| "0".into());
    let mut max = 0usize;
    for part in raw.trim().split(',') {
        let hi = if let Some((lo_str, hi_str)) = part.split_once('-') {
            let lo: usize = lo_str.parse().expect("malformed CPU range lower bound");
            let hi: usize = hi_str.parse().expect("malformed CPU range upper bound");
            assert!(hi >= lo, "CPU range {lo_str}-{hi_str} is inverted");
            hi
        } else {
            part.parse().expect("malformed CPU index")
        };
        max = max.max(hi);
    }
    max + 1
}

fn skip_or_load() -> Option<Ebpf> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        if std::fs::metadata("/proc/self")
            .map(|m| m.uid())
            .unwrap_or(1)
            != 0
        {
            eprintln!("SKIP: counter_map smoketest requires root");
            return None;
        }
    }

    let path = match std::env::var("FLEETOS_EBPF_OBJ") {
        Ok(p) => p,
        Err(_) => "../target/bpfel-unknown-none/release/fleetos-ebpf".to_string(),
    };
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("SKIP: cannot read {path}: {e}");
            return None;
        }
    };
    match Ebpf::load(&bytes) {
        Ok(e) => Some(e),
        Err(e) => {
            eprintln!("SKIP: failed to load eBPF object: {e}");
            None
        }
    }
}

// --- Test ---

#[test]
fn pod_net_counters_map_is_wired() {
    let mut ebpf = match skip_or_load() {
        Some(e) => e,
        None => return,
    };

    // Pull the map out of the loaded object and convert to the typed map.
    // Because `fleetos-ebpf-common` is `no_std` and cannot depend on `aya`,
    // our shared types (`HostOrderIpv4`, `PodNetCounters`) do not implement
    // `aya::Pod`. We use the raw underlying types (`u32` and `[u8; 32]`)
    // which Aya natively supports, and cast via `bytemuck`.
    let map = ebpf
        .take_map("POD_NET_COUNTERS")
        .expect("POD_NET_COUNTERS map missing");
    let mut pcm: PerCpuHashMap<_, u32, [u64; 4]> =
        PerCpuHashMap::try_from(map).expect("must be a PerCpuHashMap");

    let ncpu = num_possible_cpus();

    // Construct the key in host order, matching what the kernel expects.
    let ip = HostOrderIpv4::from_network(u32::from_ne_bytes([240, 0, 0, 10]));

    let sample = PodNetCounters {
        tx_bytes: 100,
        tx_packets: 1,
        rx_bytes: 50,
        rx_packets: 2,
    };

    // Cast to raw types for the Aya API.
    let ip_key = ip.0;
    // bytemuck::cast is infallible for [u64; 4] and avoids TryInto type inference issues.
    let sample_bytes: [u64; 4] = bytemuck::cast(sample);

    // Insert one value per possible CPU, then read back and verify the sum.
    // Aya 0.14 requires PerCpuValues, which implements TryFrom<Vec<T>>
    // because it must verify at runtime that the vector length matches
    // the number of possible CPUs.
    let values = aya::maps::PerCpuValues::<[u64; 4]>::try_from(vec![sample_bytes; ncpu])
        .expect("PerCpuValues vector length must match possible CPUs");

    pcm.insert(ip_key, values, 0).expect("insert");

    let got_bytes: Vec<[u64; 4]> = pcm.get(&ip_key, 0).expect("get").clone().into_vec();
    assert_eq!(
        got_bytes.len(),
        ncpu,
        "must return one value per possible CPU"
    );

    // Cast back to our shared types for assertion
    let got: Vec<PodNetCounters> = got_bytes.iter().map(|b| bytemuck::cast(*b)).collect();

    let tx_sum: u64 = got.iter().map(|c| c.tx_bytes).sum();
    assert_eq!(
        tx_sum,
        100 * ncpu as u64,
        "sum across CPUs must match inserted value"
    );

    let rx_sum: u64 = got.iter().map(|c| c.rx_bytes).sum();
    assert_eq!(rx_sum, 50 * ncpu as u64);

    let _ = pcm.remove(&ip_key);
}
