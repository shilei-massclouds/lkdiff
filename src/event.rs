//! Trace event.

use crate::errno::errno_name;
use crate::mmap::{map_name, prot_name};
use crate::sysno::*;
use std::ffi::CStr;
use std::fmt::{Display, Formatter};
use std::mem;

pub const USER_ECALL: u64 = 8;

const AT_FDCWD: u64 = -100i64 as u64;

#[repr(C)]
pub struct TraceHead {
    pub magic: u16,
    /// TraceHead size
    pub headsize: u16,
    /// TraceEvent size
    pub totalsize: u32,
    /// in/out 1/0
    pub inout: u64,
    pub cause: u64,
    pub epc: u64,
    /// riscv a0-a7
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

#[derive(Debug)]
#[repr(C)]
pub struct KStat {
    st_dev: u64,
    st_ino: u64,
    st_mode: u32,
    st_nlink: u32,
    st_uid: u32,
    st_gid: u32,
    st_rdev: u64,
    _pad0: u64,
    st_size: u64,
    st_blksize: u32,
    _pad1: u32,
    st_blocks: u64,
    st_atime_sec: isize,
    st_atime_nsec: isize,
    st_mtime_sec: isize,
    st_mtime_nsec: isize,
    st_ctime_sec: isize,
    st_ctime_nsec: isize,
}
const KSTAT_SIZE: usize = mem::size_of::<KStat>();

impl TraceEvent {
    pub fn handle_syscall(&self, args: &mut Vec<String>) -> (&'static str, usize, String) {
        match self.head.ax[7] {
            LINUX_SYSCALL_IOCTL => self.do_common("ioctl", 3),
            LINUX_SYSCALL_FACCESSAT => self.do_faccessat(args),
            LINUX_SYSCALL_OPENAT => self.do_openat(args),
            LINUX_SYSCALL_CLOSE => self.do_common("close", 1),
            LINUX_SYSCALL_READ => self.do_read(args),
            LINUX_SYSCALL_WRITE => self.do_write(args),
            LINUX_SYSCALL_FSTATAT => self.do_fstatat(args),
            LINUX_SYSCALL_EXIT_GROUP => ("exit_group", 7, format!("{:#x}", self.result)),
            LINUX_SYSCALL_SET_TID_ADDRESS => self.do_common("set_tid_address", 1),
            LINUX_SYSCALL_SET_ROBUST_LIST => self.do_common("set_robust_list", 2),
            LINUX_SYSCALL_CLOCK_GETTIME => self.do_common("clock_gettime", 2),
            LINUX_SYSCALL_UNAME => self.do_uname(args),
            LINUX_SYSCALL_BRK => self.do_common("brk", 1),
            LINUX_SYSCALL_MMAP => self.do_mmap(args),
            LINUX_SYSCALL_MPROTECT => self.do_common("mprotect", 3),

            LINUX_SYSCALL_PRLIMIT64 => self.do_common("prlimit64", 4),
            LINUX_SYSCALL_GETRANDOM => self.do_common("getrandom", 3),
            _ => ("[unknown sysno]", 7, format!("{:#x}", self.result)),
        }
    }

    #[inline]
    fn do_common(&self, name: &'static str, argc: usize) -> (&'static str, usize, String) {
        if (self.result as i64) <= 0 {
            (name, argc, format!("{}", errno_name(self.result as i32)))
        } else {
            (name, argc, format!("{:#x}", self.result))
        }
    }

    fn do_path(&self, args: &mut Vec<String>) {
        assert!(self.payloads.len() >= 1);
        let payload = &self.payloads.first().unwrap();
        //assert_eq!(payload.inout, crate::IN);
        assert_eq!(payload.index, 1);
        let fname = CStr::from_bytes_until_nul(&payload.data).unwrap();
        let fname = match fname.to_str() {
            Ok(name) => {
                format!("\"{}\"", name)
            }
            Err(_) => "[!parse_str_err!]".to_string(),
        };
        args[payload.index] = fname;
    }

    fn do_openat(&self, args: &mut Vec<String>) -> (&'static str, usize, String) {
        if self.head.ax[0] == AT_FDCWD {
            args[0] = "AT_FDCWD".to_string();
        }
        self.do_path(args);
        self.do_common("openat", 4)
    }

    fn do_faccessat(&self, args: &mut Vec<String>) -> (&'static str, usize, String) {
        if self.head.ax[0] == AT_FDCWD {
            args[0] = "AT_FDCWD".to_string();
        }
        self.do_path(args);
        // For faccessat, there're 3 args, NO 'flags'.
        // For faccessat2, there're 4 args with 'flags'.
        self.do_common("faccessat", 3)
    }

    fn do_fstatat(&self, args: &mut Vec<String>) -> (&'static str, usize, String) {
        if self.head.ax[0] == AT_FDCWD {
            args[0] = "AT_FDCWD".to_string();
        }
        self.do_path(args);
        if self.result == 0 {
            assert_eq!(self.payloads.len(), 2);
            for payload in &self.payloads {
                if payload.index == 2 {
                    args[payload.index] = self.handle_stat(payload);
                }
            }
        }
        self.do_common("fstatat", 4)
    }

    fn handle_stat(&self, payload: &TracePayload) -> String {
        assert_eq!(payload.inout, crate::OUT);
        assert_eq!(payload.index, 2);
        let mut buf = [0u8; KSTAT_SIZE];
        buf.clone_from_slice(&payload.data[..KSTAT_SIZE]);

        let k = unsafe { mem::transmute::<[u8; KSTAT_SIZE], KStat>(buf) };
        format!(
            "{{dev={:#x}, ino={}, mode={:#o}, nlink={}, rdev={}, size={}, blksize={}, blocks={}}}",
            k.st_dev,
            k.st_ino,
            k.st_mode,
            k.st_nlink,
            k.st_rdev,
            k.st_size,
            k.st_blksize,
            k.st_blocks
        )
    }

    fn do_uname(&self, args: &mut Vec<String>) -> (&'static str, usize, String) {
        assert_eq!(self.payloads.len(), 1);
        let payload = &self.payloads.first().unwrap();
        assert_eq!(payload.inout, crate::OUT);
        assert_eq!(payload.index, 0);
        let mut buf = [0u8; UTSNAME_SIZE];
        buf.clone_from_slice(&payload.data[..UTSNAME_SIZE]);

        let utsname = unsafe { mem::transmute::<[u8; UTSNAME_SIZE], UTSName>(buf) };

        let mut names = Vec::with_capacity(6);
        for i in 0..utsname.fields.len() {
            let fname = CStr::from_bytes_until_nul(&utsname.fields[i][..]).unwrap();
            names.push(format!("{:?}", fname));
        }
        let r_uname = names.join(", ");
        args[payload.index] = format!("{{{}}}", r_uname);
        ("uname", 1, format!("{:#x}", self.result))
    }

    fn do_mmap(&self, args: &mut Vec<String>) -> (&'static str, usize, String) {
        if self.head.ax[0] == 0 {
            args[0] = String::from("NULL");
        }
        args[2] = prot_name(self.head.ax[2]);
        args[3] = map_name(self.head.ax[3]);
        args[4] = format!("{}", self.head.ax[4] as isize); // fd
        if (self.result as i64) <= 0 {
            ("mmap", 6, String::from("MAP_FAILED")) // On error, the value MAP_FAILED(that is, (void *) -1) is returned,
        } else {
            ("mmap", 6, format!("{:#x}", self.result)) // On success, mmap() returns a pointer to the mapped area.
        }
    }

    fn do_write(&self, args: &mut Vec<String>) -> (&'static str, usize, String) {
        assert_eq!(self.payloads.len(), 1);
        let payload = &self.payloads.first().unwrap();
        assert_eq!(payload.inout, crate::OUT);
        assert_eq!(payload.index, 1);
        args[0] = format!("{}", self.head.ax[0] as isize); // fd
        args[payload.index] = match CStr::from_bytes_until_nul(&payload.data) {
            Ok(content) => {
                format!("{:?}", content)
            }
            Err(_) => "[!parse_str_err!]".to_string(),
        };

        ("write", 3, format!("{:#x}", self.result))
    }

    fn do_read(&self, args: &mut Vec<String>) -> (&'static str, usize, String) {
        assert_eq!(self.payloads.len(), 1);
        let payload = &self.payloads.first().unwrap();
        assert_eq!(payload.inout, crate::OUT);
        assert_eq!(payload.index, 1);
        args[0] = format!("{}", self.head.ax[0] as isize); // fd
        args[payload.index] = match CStr::from_bytes_until_nul(&payload.data) {
            Ok(content) => {
                format!("{:?}", content)
            }
            Err(_) => "[!parse_str_err!]".to_string(),
        };

        ("read", 3, format!("{:#x}", self.result))
    }
}

impl Display for TraceEvent {
    fn fmt(&self, fmt: &mut Formatter) -> std::fmt::Result {
        assert_eq!(self.head.cause, USER_ECALL);

        let mut args = self.head.ax[..7]
            .iter()
            .map(|arg| format!("{:#x}", arg))
            .collect::<Vec<_>>();

        let (syscall, argc, result) = self.handle_syscall(&mut args);

        write!(
            fmt,
            "[{}]{}({}) -> {}, usp: {:#x}",
            self.head.ax[7],
            syscall,
            args[..argc].join(", "),
            result,
            self.head.usp
        )
    }
}
