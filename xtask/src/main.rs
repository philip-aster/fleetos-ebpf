// xtask/src/main.rs
// Build runner that invokes cargo to compile kernel eBPF bytecode

use anyhow::{Result, bail};
use std::process::Command;

fn main() -> Result<()> {
    println!("Compiling FleetOS eBPF kernel programs...");

    let status = Command::new("cargo")
        .args([
            "+nightly",
            "build",
            "--package",
            "ebpf",
            "--target",
            "bpfel-unknown-none",
            "-Z",
            "build-std=core",
            "--release",
        ])
        .status()?;

    if !status.success() {
        bail!("eBPF kernel compilation failed");
    }

    println!("eBPF bytecode compiled successfully to target/bpfel-unknown-none/release/ebpf.");
    Ok(())
}
