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
