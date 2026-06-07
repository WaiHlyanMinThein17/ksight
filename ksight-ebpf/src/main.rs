#![no_std]
#![no_main]

#[allow(
    clippy::all,
    dead_code,
    improper_ctypes_definitions,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unnecessary_transmutes,
    unsafe_op_in_unsafe_fn,
)]
#[rustfmt::skip]
mod vmlinux;

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_task,
        bpf_probe_read_kernel, bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use ksight_common::{Event, EventKind, EventPayload, ExecPayload, PATH_LEN};
use vmlinux::task_struct;

const FILENAME_OFFSET: usize = 24;

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
    let ppid = unsafe {
        let task = bpf_get_current_task() as *const task_struct;
        if task.is_null() { 0 } else { read_ppid(task).unwrap_or(0) }
    };

    let event = Event {
        kind: EventKind::Exec,
        payload: EventPayload {
            exec: ExecPayload { pid, ppid, comm },
        },
    };

    if let Some(mut entry) = EVENTS.reserve::<Event>(0) {
        entry.write(event);
        entry.submit(0);
    }
    Ok(0)
}

#[tracepoint]
pub fn ksight_open(ctx: TracePointContext) -> u32 {
    match try_open(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_open(ctx: TracePointContext) -> Result<u32, u32> {
    let comm = match bpf_get_current_comm() {
        Ok(comm) => comm,
        Err(_) => return Ok(0),
    };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    let filename_ptr: *const u8 = match unsafe { ctx.read_at(FILENAME_OFFSET) } {
        Ok(ptr) => ptr,
        Err(_) => return Ok(0),
    };

    let Some(mut entry) = EVENTS.reserve::<Event>(0) else {
        return Ok(0);
    };

    let ev = entry.as_mut_ptr();
    unsafe {
        (*ev).kind = EventKind::Open;
        (*ev).payload.open.pid = pid;
        (*ev).payload.open.comm = comm;
        let buf = &mut (*ev).payload.open.filename;
        *buf = [0u8; PATH_LEN];
        if bpf_probe_read_user_str_bytes(filename_ptr, buf).is_err() {
            entry.discard(0);
            return Ok(0);
        }
    }
    entry.submit(0);
    Ok(0)
}

unsafe fn read_ppid(task: *const task_struct) -> Result<u32, i64> {
    unsafe {
        let parent: *const task_struct =
            bpf_probe_read_kernel(&(*task).real_parent)? as *const task_struct;
        if parent.is_null() {
            return Ok(0);
        }
        let tgid: i32 = bpf_probe_read_kernel(&(*parent).tgid)?;
        Ok(tgid as u32)
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
