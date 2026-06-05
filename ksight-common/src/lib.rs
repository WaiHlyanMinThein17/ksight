#![no_std]

/// A process-execution event, produced by the eBPF program in kernel space
/// and consumed by the agent in user space.
///
/// `#[repr(C)]` pins the memory layout so both sides agree byte-for-byte:
/// the kernel writes these bytes into the ring buffer, and the agent reads
/// the same bytes back as this struct. Rust's default layout is unspecified
/// and may reorder fields, which would make that reinterpretation unsound.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecEvent {
    /// Process ID (the TGID: what userspace calls a PID).
    pub pid: u32,
    /// Command name (TASK_COMM_LEN = 16 bytes, NUL-padded). Fixed-size
    /// because there is no heap in the kernel program.
    pub comm: [u8; 16],
}
