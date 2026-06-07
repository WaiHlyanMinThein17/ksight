use std::borrow::Cow;

use aya::{maps::RingBuf, programs::TracePoint};
use log::debug;
use tokio::io::unix::AsyncFd;

use ksight_common::{Event, EventKind};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/ksight"
    )))?;

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        debug!("eBPF logger not initialized: {e}");
    }

    let exec: &mut TracePoint = ebpf.program_mut("ksight_exec").unwrap().try_into()?;
    exec.load()?;
    exec.attach("syscalls", "sys_enter_execve")?;

    let open: &mut TracePoint = ebpf.program_mut("ksight_open").unwrap().try_into()?;
    open.load()?;
    open.attach("syscalls", "sys_enter_openat")?;

    let ring = RingBuf::try_from(ebpf.take_map("EVENTS").unwrap())?;
    let mut async_fd = AsyncFd::new(ring)?;

    println!("ksight: tracing exec + open. Ctrl-C to stop.");

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

fn bytes_to_str(buf: &[u8]) -> Cow<'_, str> {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end])
}
