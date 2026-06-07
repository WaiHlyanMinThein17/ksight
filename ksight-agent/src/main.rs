use std::time::Duration;

use aya::{
    maps::{Array, PerCpuArray, RingBuf},
    programs::TracePoint,
};
use clap::Parser;
use crossterm::event::{Event as TermEvent, EventStream, KeyCode, KeyEventKind};
use log::debug;
use tokio::io::unix::AsyncFd;

use ksight_common::{
    COMM_LEN, Event, EventKind, FILTER_MODE_COMM, FILTER_MODE_NONE, FILTER_MODE_PID, Filter,
};
use ksight_tui::{AppState, render};

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

fn filter_label(args: &Args) -> String {
    if let Some(pid) = args.pid {
        format!("pid={}", pid)
    } else if let Some(comm) = &args.comm {
        format!("comm={}", comm)
    } else {
        "none".to_string()
    }
}

fn update_histogram(
    hist: &PerCpuArray<impl core::borrow::Borrow<aya::maps::MapData>, u64>,
    state: &mut AppState,
) -> anyhow::Result<()> {
    for (bucket, slot) in state.histogram.iter_mut().enumerate() {
        let per_cpu = hist.get(&(bucket as u32), 0)?;
        *slot = per_cpu.iter().sum();
    }
    Ok(())
}

fn format_event(event: &Event) -> String {
    match event.kind {
        EventKind::Exec => {
            let p = unsafe { event.payload.exec };
            format!(
                "EXEC  pid={:<8} ppid={:<8} comm={}",
                p.pid,
                p.ppid,
                bytes_to_str(&p.comm)
            )
        }
        EventKind::Open => {
            let p = unsafe { event.payload.open };
            format!(
                "OPEN  pid={:<8} comm={:<16} {}",
                p.pid,
                bytes_to_str(&p.comm),
                bytes_to_str(&p.filename)
            )
        }
    }
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

    let mut state = AppState::new(filter_label(&args));
    let mut reader = EventStream::new();
    let mut ticker = tokio::time::interval(Duration::from_millis(500));

    let mut terminal = ratatui::init();
    let result = run(
        &mut terminal,
        &mut state,
        &mut async_fd,
        &hist,
        &mut reader,
        &mut ticker,
    )
    .await;
    ratatui::restore();
    result
}

async fn run(
    terminal: &mut ratatui::DefaultTerminal,
    state: &mut AppState,
    async_fd: &mut AsyncFd<RingBuf<aya::maps::MapData>>,
    hist: &PerCpuArray<aya::maps::MapData, u64>,
    reader: &mut EventStream,
    ticker: &mut tokio::time::Interval,
) -> anyhow::Result<()> {
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                update_histogram(hist, state)?;
                terminal.draw(|f| render(f, state))?;
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
                    state.push_event(format_event(&event));
                }
                guard.clear_ready();
                terminal.draw(|f| render(f, state))?;
            }
            maybe_key = futures::StreamExt::next(reader) => {
                if let Some(Ok(TermEvent::Key(key))) = maybe_key
                    && key.kind == KeyEventKind::Press
                    && key.code == KeyCode::Char('q')
                {
                    break;
                }
            }
        }
    }
    Ok(())
}

fn bytes_to_str(buf: &[u8]) -> std::borrow::Cow<'_, str> {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end])
}
