// ebpf/src/main.rs
// Kernel entrypoint for Aya 0.2.x (Traffic Control Classifier & Sockops)

#![no_std]
#![no_main]

mod maps;

use aya_ebpf::{
    macros::{classifier, sock_ops},
    programs::{SockOpsContext, TcContext},
};
use aya_log_ebpf::info;
use fleetos_ebpf_common::{EbpfPolicyKey, FleetosHeader};
use maps::POLICY_MAP;

/// Linux Traffic Control (tc) return codes
const TC_ACT_OK: i32 = 0; // Pass packet through network stack
const TC_ACT_SHOT: i32 = 2; // Drop packet in kernel immediately

/// Bare-metal eBPF target panic handler.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

/// Ingress Traffic Control (tc) packet classifier program.
#[classifier]
pub fn tc_ingress_filter(ctx: TcContext) -> i32 {
    info!(&ctx, "eBPF ingress filter evaluating packet");
    match unsafe { try_tc_ingress_filter(&ctx) } {
        Ok(action) => action,
        Err(_) => TC_ACT_SHOT, // Default-deny on parse or bounds check failure
    }
}

/// Safely inspect packet data using strict eBPF verifier bounds checking.
unsafe fn try_tc_ingress_filter(ctx: &TcContext) -> Result<i32, ()> {
    // 1. Dereference raw skb pointers within explicit unsafe blocks
    let data = unsafe { (*ctx.skb.skb).data as usize };
    let data_end = unsafe { (*ctx.skb.skb).data_end as usize };

    // 2. Verify packet buffer is large enough for FleetosHeader
    let header_len = core::mem::size_of::<FleetosHeader>();
    if data + header_len > data_end {
        return Ok(TC_ACT_OK); // Allow standard non-overlay packets
    }

    // 3. Read FleetOS header from skb memory pointer
    let header = unsafe { &*(data as *const FleetosHeader) };

    // 4. Verify FleetOS overlay signature ("FL" = 0x464C)
    if header.magic != 0x464C {
        return Ok(TC_ACT_OK);
    }

    // 5. Construct BPF Map lookup key using typed IdentityHash fields
    let key = EbpfPolicyKey {
        src_hash: header.src_hash,
        dst_hash: header.dst_hash,
        port: header.port,
        _pad: 0,
    };

    // 6. Query eBPF Policy Map
    if let Some(val) = unsafe { POLICY_MAP.get(&key) } {
        if val.action == 1 {
            return Ok(TC_ACT_OK); // ALLOW
        }
    }

    // 7. Unauthorized packet -> DROP
    Ok(TC_ACT_SHOT)
}

/// Socket Operations hook for tracking socket state transitions
#[sock_ops]
pub fn sockops_identity_hook(_ctx: SockOpsContext) -> u32 {
    0
}
