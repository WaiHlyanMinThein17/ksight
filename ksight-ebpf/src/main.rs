#![no_std]
#![no_main]

#[allow(
    clippy::all,
    dead_code,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals
)]
#[rustfmt::skip]
mod vmlinux;

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_task, bpf_probe_read_kernel},
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use ksight_common::ExecEvent;
use vmlinux::task_struct;

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
    let comm = match bpf_get_current_comm() {
        Ok(comm) => comm,
        Err(_) => return Ok(0),
    };

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    // ppid via CO-RE. bpf_get_current_task() returns a raw *mut task_struct.
    // We read real_parent (a *mut task_struct), then that parent's tgid.
    // Each read goes through bpf_probe_read_kernel, which the verifier allows
    // (it can fault safely), and because the aya-tool-generated task_struct
    // carries preserve_access_index, the field offsets are CO-RE-relocated
    // against the running kernel's BTF at load time -- not hardcoded.
    let ppid = unsafe {
        let task = bpf_get_current_task() as *const task_struct;
        if task.is_null() {
            0
        } else {
            match read_ppid(task) {
                Ok(p) => p,
                Err(_) => 0,
            }
        }
    };

    let event = ExecEvent { pid, ppid, comm };

    match EVENTS.reserve::<ExecEvent>(0) {
        Some(mut entry) => {
            entry.write(event);
            entry.submit(0);
        }
        None => {}
    }

    Ok(0)
}

/// Read real_parent->tgid from a task_struct via two CO-RE-relocated reads.
unsafe fn read_ppid(task: *const task_struct) -> Result<u32, i64> {
    // real_parent is a *mut task_struct field of task_struct.
    let parent: *const task_struct =
        bpf_probe_read_kernel(&(*task).real_parent)? as *const task_struct;
    if parent.is_null() {
        return Ok(0);
    }
    // tgid is the parent's thread-group id == the parent's "PID" in user terms.
    let tgid: i32 = bpf_probe_read_kernel(&(*parent).tgid)?;
    Ok(tgid as u32)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
