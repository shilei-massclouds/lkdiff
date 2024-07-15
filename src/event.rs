//! Trace event.

use std::ffi::CStr;
use std::fmt::{Display, Formatter};
use std::mem;
use crate::errno::errno_name;

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
    pub usp: u64,
    pub stack: [u64; 8],
    pub orig_a0: u64,
}

pub struct TracePayload {
    pub inout: u64,
    pub index: usize,
    pub data: Vec<u8>,
}

pub struct TraceEvent {
    pub head: TraceHead,
    pub result: u64,
    pub payloads: Vec<TracePayload>,
}

const UTS_LEN: usize = 64;

#[repr(C)]
struct UTSName {
    fields: [[u8; UTS_LEN + 1]; 6],
}
const UTSNAME_SIZE: usize = mem::size_of::<UTSName>();

impl TraceEvent {
    pub fn handle_syscall(&self, args: &mut Vec<String>) -> (&'static str, usize, String) {
        match self.head.ax[7] {
            0x1d => ("ioctl", 7, format!("{:#x}", self.result)),
            0x30 => ("faccessat", 7, format!("{:#x}", self.result)),
            0x38 => self.do_openat(args),
            0x39 => ("close", 7, format!("{:#x}", self.result)),
            0x3f => ("read", 7, format!("{:#x}", self.result)),
            0x40 => ("write", 7, format!("{:#x}", self.result)),
            0x4f => ("fstatat", 7, format!("{:#x}", self.result)),
            0x5e => ("exit_group", 7, format!("{:#x}", self.result)),
            0x60 => ("set_tid_address", 7, format!("{:#x}", self.result)),
            0x63 => ("set_robust_list", 7, format!("{:#x}", self.result)),
            0x71 => ("clock_gettime", 7, format!("{:#x}", self.result)),
            0xa0 => self.do_uname(args),
            0xd6 => self.do_common("brk", 1),
            0xde => ("mmap", 7, format!("{:#x}", self.result)),
            0xe2 => ("mprotect", 7, format!("{:#x}", self.result)),

            0x105 => ("prlimit64", 7, format!("{:#x}", self.result)),
            0x116 => ("getrandom", 7, format!("{:#x}", self.result)),
            _ => {
                ("[unknown sysno]", 7, format!("{:#x}", self.result))
            },
        }
    }

    #[inline]
    fn do_common(&self, name: &'static str, argc: usize) -> (&'static str, usize, String) {
        (name, argc, format!("{:#x}", self.result))
    }

    fn do_openat(&self, args: &mut Vec<String>) -> (&'static str, usize, String) {
        if self.head.ax[0] == AT_FDCWD {
            args[0] = "AT_FDCWD".to_string();
        }
        assert_eq!(self.payloads.len(), 1);
        let payload = &self.payloads.first().unwrap();
        // argc: 4: dfd fname flags mode
        assert_eq!(payload.inout, crate::IN);
        assert_eq!(payload.index, 1);
        let fname = CStr::from_bytes_until_nul(&payload.data).unwrap();
        let fname = format!("\"{}\"", fname.to_str().unwrap());
        args[payload.index] = fname.to_string();

        ("openat", 4, format!("{}", errno_name(self.result as i32)))
    }

    fn do_uname(&self, args: &mut Vec<String>) -> (&'static str, usize, String) {
        assert_eq!(self.payloads.len(), 1);
        let payload = &self.payloads.first().unwrap();
        assert_eq!(payload.inout, crate::OUT);
        assert_eq!(payload.index, 0);
        let mut buf = [0u8; UTSNAME_SIZE];
        buf.clone_from_slice(&payload.data[..UTSNAME_SIZE]);

        let utsname = unsafe {
            mem::transmute::<[u8; UTSNAME_SIZE], UTSName>(buf)
        };

        let mut names = Vec::with_capacity(6);
        for i in 0..utsname.fields.len() {
            let fname = CStr::from_bytes_until_nul(&utsname.fields[i][..]).unwrap();
            names.push(format!("{:?}", fname));
        }
        let r_uname = names.join(", ");
        args[payload.index] = format!("{{{}}}", r_uname);
        ("uname", 1, format!("{:#x}", self.result))
    }
}

impl Display for TraceEvent {
    fn fmt(&self, fmt: &mut Formatter) -> std::fmt::Result {
        assert_eq!(self.head.cause, USER_ECALL);

        let mut args = self.head.ax[..7].iter().map(|arg|
            format!("{:#x}", arg)
        ).collect::<Vec<_>>();

        let (syscall, argc, result) = self.handle_syscall(&mut args);

        write!(fmt, "[{}]{}({}) -> {}, usp: {:#x}",
            self.head.ax[7], syscall, args[..argc].join(", "), result,
            self.head.usp)
    }
}
