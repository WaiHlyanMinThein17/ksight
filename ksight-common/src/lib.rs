#![no_std]

pub const COMM_LEN: usize = 16;
pub const PATH_LEN: usize = 256;

#[repr(u32)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    Exec = 0,
    Open = 1,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecPayload {
    pub pid: u32,
    pub ppid: u32,
    pub comm: [u8; COMM_LEN],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct OpenPayload {
    pub pid: u32,
    pub comm: [u8; COMM_LEN],
    pub filename: [u8; PATH_LEN],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union EventPayload {
    pub exec: ExecPayload,
    pub open: OpenPayload,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Event {
    pub kind: EventKind,
    pub payload: EventPayload,
}

#[repr(u32)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FilterMode {
    None = 0,
    Pid = 1,
    Comm = 2,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Filter {
    pub mode: u32,
    pub pid: u32,
    pub comm: [u8; COMM_LEN],
    pub comm_len: u32,
}

pub const FILTER_MODE_NONE: u32 = 0;
pub const FILTER_MODE_PID: u32 = 1;
pub const FILTER_MODE_COMM: u32 = 2;

#[cfg(feature = "user")]
unsafe impl aya::Pod for Filter {}

pub const HIST_BUCKETS: usize = 64;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RequestKey {
    pub sector: u64,
    pub dev: u32,
    pub _pad: u32,
}
