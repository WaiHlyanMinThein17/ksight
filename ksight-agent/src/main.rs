use std::borrow::Cow;

use aya::{
    maps::{Array, PerCpuArray, RingBuf},
    programs::TracePoint,
};
use clap::Parser;
use log::debug;
use tokio::io::unix::AsyncFd;

use ksight_common::{
    COMM_LEN, Event, EventKind, FILTER_MODE_COMM, FILTER_MODE_NONE, FILTER_MODE_PID, Filter,
    HIST_BUCKETS,
};

#[derive(Parser)]
#[command(about = "eBPF process exec + file open tracer with block I/O latency histogram")]
struct Args {
    #[arg(long, conflicts_with = "comm")]
    pid: Option<u32>,
    #[arg(long)]
    comm: Option<String>,
}

fn build_filter(args: &Args) -> Filter {
    let mut filter = Filter {
        mode: FILTER_MODE_NONE,
        pid: 0,
        comm: [0u8; COMM_LEN],
        comm_len: 0,
    };
    if let Some(pid) = args.pid {
        filter.mode = FILTER_MODE_PID;
        filter.pid = pid;
    } else if let Some(comm) = &args.comm {
        filter.mode = FILTER_MODE_COMM;
        let bytes = comm.as_bytes();
        let len = bytes.len().min(COMM_LEN);
        filter.comm[..len].copy_from_slice(&bytes[..len]);
        filter.comm_len = len as u32;
    }
    filter
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let args = Args::parse();

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/ksight"
    )))?;

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        debug!("eBPF logger not initialized: {e}");
    }

    let mut filter_map: Array<_, Filter> = Array::try_from(ebpf.take_map("FILTER").unwrap())?;
    filter_map.set(0, build_filter(&args), 0)?;

    let exec: &mut TracePoint = ebpf.program_mut("ksight_exec").unwrap().try_into()?;
    exec.load()?;
    exec.attach("syscalls", "sys_enter_execve")?;

    let open: &mut TracePoint = ebpf.program_mut("ksight_open").unwrap().try_into()?;
    open.load()?;
    open.attach("syscalls", "sys_enter_openat")?;

    let issue: &mut TracePoint = ebpf.program_mut("ksight_block_issue").unwrap().try_into()?;
    issue.load()?;
    issue.attach("block", "block_rq_issue")?;

    let complete: &mut TracePoint = ebpf
        .program_mut("ksight_block_complete")
        .unwrap()
        .try_into()?;
    complete.load()?;
    complete.attach("block", "block_rq_complete")?;

    let hist: PerCpuArray<_, u64> = PerCpuArray::try_from(ebpf.take_map("HIST").unwrap())?;
    let ring = RingBuf::try_from(ebpf.take_map("EVENTS").unwrap())?;
    let mut async_fd = AsyncFd::new(ring)?;

    println!("ksight: tracing exec + open + block I/O latency. Ctrl-C to stop.");

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
                    if bytes.len() < size_of::<Event>() {
                        continue;
                    }
                    let event: Event =
                        unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const Event) };
                    print_event(&event);
                }
                guard.clear_ready();
            }
        }
    }

    print_histogram(&hist)?;
    Ok(())
}

fn print_event(event: &Event) {
    match event.kind {
        EventKind::Exec => {
            let p = unsafe { event.payload.exec };
            println!(
                "EXEC  pid={:<8} ppid={:<8} comm={}",
                p.pid,
                p.ppid,
                bytes_to_str(&p.comm)
            );
        }
        EventKind::Open => {
            let p = unsafe { event.payload.open };
            println!(
                "OPEN  pid={:<8} comm={:<16} {}",
                p.pid,
                bytes_to_str(&p.comm),
                bytes_to_str(&p.filename)
            );
        }
    }
}

fn print_histogram(
    hist: &PerCpuArray<impl core::borrow::Borrow<aya::maps::MapData>, u64>,
) -> anyhow::Result<()> {
    let mut totals = [0u64; HIST_BUCKETS];
    for bucket in 0..HIST_BUCKETS {
        let per_cpu = hist.get(&(bucket as u32), 0)?;
        totals[bucket] = per_cpu.iter().sum();
    }

    let max = totals.iter().copied().max().unwrap_or(0);
    if max == 0 {
        println!("\nNo block I/O recorded.");
        return Ok(());
    }

    println!("\nBlock I/O latency histogram:");
    println!("{:>18} {:>10}  {}", "usec", "count", "distribution");
    for (b, &count) in totals.iter().enumerate() {
        if count == 0 {
            continue;
        }
        let low_us = (1u64 << b) / 1000;
        let high_us = ((1u64 << b) * 2 - 1) / 1000;
        let range = format!("{} -> {}", low_us, high_us);
        let bar_len = (count as usize * 40 / max as usize).max(1);
        let bar: String = core::iter::repeat('*').take(bar_len).collect();
        println!("{:>18} {:>10}  {}", range, count, bar);
    }
    Ok(())
}
fn bytes_to_str(buf: &[u8]) -> Cow<'_, str> {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end])
}
