// xtask/src/main.rs
use anyhow::Result;
use std::process::Command;

fn main() -> Result<()> {
    println!("Compiling FleetOS eBPF kernel programs...");

    let status = Command::new("cargo")
        .args(&[
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
        anyhow::bail!("eBPF build failed");
    }

    println!("eBPF bytecode compiled successfully.");
    Ok(())
}
