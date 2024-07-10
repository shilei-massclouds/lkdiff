//! Trace event.

use std::ffi::CStr;
use std::fmt::{Display, Formatter};

pub const USER_ECALL: u64 = 8;

const AT_FDCWD: u64 = -100i64 as u64;

#[repr(C)]
pub struct TraceHead {
    pub magic: u16,
    pub headsize: u16,
    pub totalsize: u32,
    pub inout: u64,
    pub cause: u64,
    pub epc: u64,
    pub ax: [u64; 8],
}

pub struct TracePayload {
    pub index: usize,
    pub data: Vec<u8>,
}

pub struct TraceEvent {
    pub head: TraceHead,
    pub result: u64,
    pub payloads: Vec<TracePayload>,
}

impl TraceEvent {
    pub fn handle_syscall(&self, args: &mut Vec<String>) -> (&'static str, usize, String) {
        match self.head.ax[7] {
            0x38 => {
                self.do_openat(args)
            },
            _ => {
                ("[unknown sysno]", 7, format!("{:#x}", self.result))
            },
        }
    }

    fn do_openat(&self, args: &mut Vec<String>) -> (&'static str, usize, String) {
        assert_eq!(self.payloads.len(), 1);
        if self.head.ax[0] == AT_FDCWD {
            args[0] = "AT_FDCWD".to_string();
        }
        for payload in &self.payloads {
            // argc: 4: dfd fname flags mode
            assert_eq!(payload.index, 1);
            let fname = CStr::from_bytes_until_nul(&payload.data).unwrap();
            let fname = format!("\"{}\"", fname.to_str().unwrap());
            println!("fname {}", fname);
            args[payload.index] = fname.to_string();
        }

        ("openat", 4, format!("{:#x}", self.result))
    }
}

impl Display for TraceEvent {
    fn fmt(&self, fmt: &mut Formatter) -> std::fmt::Result {
        assert_eq!(self.head.cause, USER_ECALL);

        let mut args = self.head.ax[..7].iter().map(|arg|
            format!("{:#x}", arg)
        ).collect::<Vec<_>>();

        let (syscall, argc, result) = self.handle_syscall(&mut args);

        write!(fmt, "[{}]{}({}) -> {}, usp: 0x0",
            self.head.ax[7], syscall, args[..argc].join(", "), result)
    }
}

/*
pub fn name(sysno: u64) -> &'static str {
    match sysno {
        0x1d => "ioctl",
        0x30 => "faccessat",
        0x38 => "openat",
        0x39 => "close",
        0x3f => "read",
        0x40 => "write",
        0x4f => "fstatat",
        0x5e => "exit_group",
        0x60 => "set_tid_address",
        0x63 => "set_robust_list",
        0x71 => "clock_gettime",
        0xa0 => "uname",
        0xd6 => "brk",
        0xde => "mmap",
        0xe2 => "mprotect",

        0x105 => "prlimit64",
        0x116 => "getrandom",
        _ => {
            panic!("unknown sysno: {}, {:#x}", sysno, sysno);
            //"[unknown sysno]"
        },
    }
}
*/
