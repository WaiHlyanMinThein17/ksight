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
    unsafe_op_in_unsafe_fn
)]
#[rustfmt::skip]
mod vmlinux;

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_task, bpf_ktime_get_ns,
        bpf_probe_read_kernel, bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::{Array, HashMap, PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use ksight_common::{
    COMM_LEN, Event, EventKind, EventPayload, ExecPayload, FILTER_MODE_COMM, FILTER_MODE_PID,
    Filter, HIST_BUCKETS, PATH_LEN, RequestKey,
};
use vmlinux::task_struct;

const FILENAME_OFFSET: usize = 24;
const DEV_OFFSET: usize = 8;
const SECTOR_OFFSET: usize = 16;

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static FILTER: Array<Filter> = Array::with_max_entries(1, 0);

#[map]
static START: HashMap<RequestKey, u64> = HashMap::with_max_entries(10240, 0);

#[map]
static HIST: PerCpuArray<u64> = PerCpuArray::with_max_entries(HIST_BUCKETS as u32, 0);

fn passes_filter(comm: &[u8; COMM_LEN], pid: u32) -> bool {
    let filter = match FILTER.get(0) {
        Some(f) => f,
        None => return true,
    };
    match filter.mode {
        FILTER_MODE_PID => pid == filter.pid,
        FILTER_MODE_COMM => {
            let len = filter.comm_len as usize;
            if len > COMM_LEN {
                return false;
            }
            let mut i = 0;
            while i < COMM_LEN {
                if i >= len {
                    break;
                }
                if comm[i] != filter.comm[i] {
                    return false;
                }
                i += 1;
            }
            true
        }
        _ => true,
    }
}

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

    if !passes_filter(&comm, pid) {
        return Ok(0);
    }

    let ppid = unsafe {
        let task = bpf_get_current_task() as *const task_struct;
        if task.is_null() {
            0
        } else {
            read_ppid(task).unwrap_or(0)
        }
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

    if !passes_filter(&comm, pid) {
        return Ok(0);
    }

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

fn request_key(ctx: &TracePointContext) -> Result<RequestKey, i64> {
    let dev: u32 = unsafe { ctx.read_at(DEV_OFFSET)? };
    let sector: u64 = unsafe { ctx.read_at(SECTOR_OFFSET)? };
    Ok(RequestKey {
        sector,
        dev,
        _pad: 0,
    })
}

#[tracepoint]
pub fn ksight_block_issue(ctx: TracePointContext) -> u32 {
    match try_block_issue(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_block_issue(ctx: &TracePointContext) -> Result<u32, i64> {
    let key = request_key(ctx)?;
    let ts = unsafe { bpf_ktime_get_ns() };
    let _ = START.insert(&key, &ts, 0);
    Ok(0)
}

#[tracepoint]
pub fn ksight_block_complete(ctx: TracePointContext) -> u32 {
    match try_block_complete(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_block_complete(ctx: &TracePointContext) -> Result<u32, i64> {
    let key = request_key(ctx)?;
    let start = match unsafe { START.get(&key) } {
        Some(ts) => *ts,
        None => return Ok(0),
    };
    let _ = START.remove(&key);

    let now = unsafe { bpf_ktime_get_ns() };
    let delta = now.saturating_sub(start);
    if delta == 0 {
        return Ok(0);
    }

    let bucket = (63 - delta.leading_zeros()) as u32;
    let bucket = if bucket >= HIST_BUCKETS as u32 {
        HIST_BUCKETS as u32 - 1
    } else {
        bucket
    };

    if let Some(slot) = HIST.get_ptr_mut(bucket) {
        unsafe {
            *slot += 1;
        }
    }
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
