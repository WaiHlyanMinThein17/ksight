use std::borrow::Cow;

use aya::{maps::RingBuf, programs::TracePoint};
use log::{debug, warn};
use tokio::io::unix::AsyncFd;

use ksight_common::ExecEvent;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Load the eBPF object embedded at compile time by build.rs. This invokes
    // the bpf() syscall and triggers the verifier.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/ksight"
    )))?;

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        debug!("eBPF logger not initialized: {e}");
    }

    // Find the tracepoint program by its function name, load and attach it.
    let program: &mut TracePoint = ebpf.program_mut("ksight_exec").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_execve")?;

    // Take ownership of the ring buffer map for reading.
    let ring = RingBuf::try_from(ebpf.take_map("EVENTS").unwrap())?;

    // The ring buffer exposes a pollable fd; wrap it in AsyncFd so we await
    // readiness instead of busy-polling.
    let mut async_fd = AsyncFd::new(ring)?;

    println!("ksight: tracing execve. Ctrl-C to stop.");

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("\nExiting.");
                break;
            }
            guard = async_fd.readable_mut() => {
                let mut guard = guard?;
                let ring = guard.get_inner_mut();
                while let Some(item) = ring.next() {
                    let bytes: &[u8] = &item;
                    if bytes.len() < size_of::<ExecEvent>() {
                        warn!("short ring buffer read: {} bytes", bytes.len());
                        continue;
                    }
                    // Reinterpret the bytes as our repr(C) struct. Sound because
                    // the kernel wrote exactly this layout; ExecEvent is Copy
                    // with no padding or invalid bit patterns. Copy out to a
                    // local so we don't hold the borrow across the next read.
                    let event: ExecEvent =
                        unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const ExecEvent) };
                    println!("pid={:<8} comm={}", event.pid, comm_to_str(&event.comm));
                }
                guard.clear_ready();
            }
        }
    }

    Ok(())
}

/// Convert a NUL-padded 16-byte kernel comm field into a printable string,
/// trimming at the first NUL. Lossy on invalid UTF-8 rather than panicking.
fn comm_to_str(comm: &[u8; 16]) -> Cow<'_, str> {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(comm.len());
    String::from_utf8_lossy(&comm[..end])
}
