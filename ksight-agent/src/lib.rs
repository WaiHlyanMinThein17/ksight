use std::borrow::Cow;

use clap::Parser;

use ksight_common::{
    COMM_LEN, Event, EventKind, FILTER_MODE_COMM, FILTER_MODE_NONE, FILTER_MODE_PID, Filter,
};

#[derive(Parser)]
#[command(about = "eBPF process exec + file open tracer with block I/O latency histogram")]
pub struct Args {
    #[arg(long, conflicts_with = "comm")]
    pub pid: Option<u32>,
    #[arg(long)]
    pub comm: Option<String>,
}

pub fn build_filter(args: &Args) -> Filter {
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

pub fn filter_label(args: &Args) -> String {
    if let Some(pid) = args.pid {
        format!("pid={}", pid)
    } else if let Some(comm) = &args.comm {
        format!("comm={}", comm)
    } else {
        "none".to_string()
    }
}

pub fn bytes_to_str(buf: &[u8]) -> Cow<'_, str> {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end])
}

pub fn format_event(event: &Event) -> String {
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

pub fn sum_per_cpu(values: &[u64]) -> u64 {
    values.iter().sum()
}

pub fn bucket_to_us(bucket: usize) -> (u64, u64) {
    let low_ns = 1u64 << bucket;
    let low_us = low_ns / 1000;
    let high_us = (low_ns.saturating_mul(2) - 1) / 1000;
    (low_us, high_us)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ksight_common::{EventKind, EventPayload, ExecPayload, OpenPayload, PATH_LEN};

    #[test]
    fn build_filter_none_when_no_args() {
        let args = Args {
            pid: None,
            comm: None,
        };
        let f = build_filter(&args);
        assert_eq!(f.mode, FILTER_MODE_NONE);
    }

    #[test]
    fn build_filter_pid_mode() {
        let args = Args {
            pid: Some(1234),
            comm: None,
        };
        let f = build_filter(&args);
        assert_eq!(f.mode, FILTER_MODE_PID);
        assert_eq!(f.pid, 1234);
    }

    #[test]
    fn build_filter_comm_mode_copies_bytes_and_len() {
        let args = Args {
            pid: None,
            comm: Some("cat".to_string()),
        };
        let f = build_filter(&args);
        assert_eq!(f.mode, FILTER_MODE_COMM);
        assert_eq!(f.comm_len, 3);
        assert_eq!(&f.comm[..3], b"cat");
        assert_eq!(f.comm[3], 0);
    }

    #[test]
    fn build_filter_truncates_overlong_comm() {
        let long = "abcdefghijklmnopqrstuvwxyz";
        let args = Args {
            pid: None,
            comm: Some(long.to_string()),
        };
        let f = build_filter(&args);
        assert_eq!(f.comm_len as usize, COMM_LEN);
        assert_eq!(&f.comm[..], &long.as_bytes()[..COMM_LEN]);
    }

    #[test]
    fn filter_label_variants() {
        assert_eq!(
            filter_label(&Args {
                pid: Some(42),
                comm: None
            }),
            "pid=42"
        );
        assert_eq!(
            filter_label(&Args {
                pid: None,
                comm: Some("cat".to_string())
            }),
            "comm=cat"
        );
        assert_eq!(
            filter_label(&Args {
                pid: None,
                comm: None
            }),
            "none"
        );
    }

    #[test]
    fn bytes_to_str_stops_at_nul() {
        assert_eq!(bytes_to_str(b"cat\0\0\0\0"), "cat");
    }

    #[test]
    fn bytes_to_str_no_nul_uses_whole_buffer() {
        assert_eq!(bytes_to_str(b"abc"), "abc");
    }

    #[test]
    fn bytes_to_str_empty() {
        assert_eq!(bytes_to_str(b""), "");
    }

    #[test]
    fn sum_per_cpu_adds_all() {
        assert_eq!(sum_per_cpu(&[1, 2, 3, 4]), 10);
        assert_eq!(sum_per_cpu(&[]), 0);
    }

    #[test]
    fn bucket_to_us_known_buckets() {
        // bucket 10 = 2^10 ns = 1024 ns = 1us low bound
        assert_eq!(bucket_to_us(10).0, 1);
        // bucket 20 = 2^20 ns = 1048576 ns = 1048us low bound
        assert_eq!(bucket_to_us(20).0, 1048);
        // high bound is one ns below the next bucket
        let (low, high) = bucket_to_us(20);
        assert!(high >= low);
    }

    #[test]
    fn format_event_exec() {
        let event = Event {
            kind: EventKind::Exec,
            payload: EventPayload {
                exec: ExecPayload {
                    pid: 100,
                    ppid: 1,
                    comm: *b"bash\0\0\0\0\0\0\0\0\0\0\0\0",
                },
            },
        };
        let s = format_event(&event);
        assert!(s.starts_with("EXEC"));
        assert!(s.contains("pid=100"));
        assert!(s.contains("ppid=1"));
        assert!(s.contains("comm=bash"));
    }

    #[test]
    fn format_event_open() {
        let mut filename = [0u8; PATH_LEN];
        filename[..9].copy_from_slice(b"/etc/motd");
        let event = Event {
            kind: EventKind::Open,
            payload: EventPayload {
                open: OpenPayload {
                    pid: 200,
                    comm: *b"cat\0\0\0\0\0\0\0\0\0\0\0\0\0",
                    filename,
                },
            },
        };
        let s = format_event(&event);
        assert!(s.starts_with("OPEN"));
        assert!(s.contains("pid=200"));
        assert!(s.contains("comm=cat"));
        assert!(s.contains("/etc/motd"));
    }
}
