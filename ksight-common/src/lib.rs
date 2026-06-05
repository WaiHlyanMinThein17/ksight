#![no_std]

/// A process-execution event, produced by the eBPF program in kernel space
/// and consumed by the agent in user space.
///
/// `#[repr(C)]` pins the memory layout so both sides agree byte-for-byte.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecEvent {
    /// Process ID (the TGID — what userspace calls a PID).
    pub pid: u32,
    /// Parent process ID (real_parent->tgid, read via CO-RE).
    pub ppid: u32,
    /// Command name (TASK_COMM_LEN = 16 bytes, NUL-padded).
    pub comm: [u8; 16],
}
