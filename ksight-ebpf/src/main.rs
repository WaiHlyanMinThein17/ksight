#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid},
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use ksight_common::ExecEvent;

/// Kernel -> user channel. A single shared ring buffer (MPSC) across all CPUs.
/// 256 KiB. Size must be a power of two and a multiple of the page size.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[tracepoint]
pub fn ksight_exec(ctx: TracePointContext) -> u32 {
    match try_exec(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_exec(_ctx: TracePointContext) -> Result<u32, u32> {
    // comm: safe wrapper returns the 16-byte command name directly, or an
    // error. On error we drop the event rather than ship a bad name.
    let comm = match bpf_get_current_comm() {
        Ok(comm) => comm,
        Err(_) => return Ok(0),
    };

    // PID: pid_tgid packs TGID (the userspace "PID") in the upper 32 bits and
    // the kernel thread id in the lower 32. We want the upper half.
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    let event = ExecEvent { pid, comm };

    // Reserve space in the ring buffer. None == buffer full; the verifier
    // requires we handle that instead of writing through a bad pointer.
    match EVENTS.reserve::<ExecEvent>(0) {
        Some(mut entry) => {
            entry.write(event);
            entry.submit(0);
        }
        None => {
            // Dropped under backpressure. Acceptable for a tracer.
        }
    }

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
