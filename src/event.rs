//! Trace event.

use std::fs::File;
use std::io::BufReader;
use crate::errno::errno_name;
use crate::mmap::{map_name, prot_name};
use crate::sysno::*;
use crate::signal::{SigAction, sig_name};
use std::ffi::CStr;
use std::fmt::{Display, Formatter};
use std::mem;
use crate::signal::{SIG_BLOCK, SIG_UNBLOCK, SIG_SETMASK};
use crate::payload::parse_payloads;
use std::io::prelude::*;
use std::io::Result;
use std::collections::HashMap;
use std::sync::Mutex;
use once_cell::unsync::Lazy;

pub const LK_MAGIC: u16 = 0xABCD;
pub const TE_SIZE: usize = mem::size_of::<TraceHead>();

pub const USER_ECALL: u64 = 8;

const AT_FDCWD: u64 = -100i64 as u64;

static TID_MAP: Mutex<Lazy<HashMap<i64, String>>> = Mutex::new(Lazy::new(|| HashMap::new()));

#[derive(Clone, Debug, Default)]
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
    pub satp: u64,
    pub tp: u64,
    pub sscratch: u64,
}

#[derive(Clone, Debug, Default)]
pub struct TracePayload {
    pub inout: u64,
    pub index: usize,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Default)]
pub enum SigStage {
    #[default]
    Empty,
    Enter(u64),
    Exit(u64),
}

#[derive(Clone, Debug, Default)]
pub struct TraceEvent {
    pub head: TraceHead,
    pub result: i64,
    pub payloads: Vec<TracePayload>,
    pub signal: SigStage,
    pub raw_fmt: bool,
    pub level: usize,
}

pub struct TraceFlow {
    pub events: Vec<TraceEvent>,
    pub signal_stack: Vec<TraceEvent>,
}

impl TraceFlow {
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            signal_stack: Vec::new(),
        }
    }
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
            SYS_IOCTL => self.do_common("ioctl", 3),
            SYS_DUP3 => self.do_common("dup3", 3),
            SYS_FACCESSAT => self.do_faccessat(args),
            SYS_OPENAT => self.do_openat(args),
            SYS_CLOSE => self.do_common("close", 1),
            SYS_LSEEK => self.do_common("lseek", 3),
            SYS_READ => self.do_read(args),
            SYS_WRITE => self.do_write(args),
            SYS_WRITEV => self.do_common("writev", 3),
            SYS_FSTATAT => self.do_fstatat(args),
            SYS_EXIT_GROUP => self.do_common("exit_group", 1),
            SYS_SET_TID_ADDRESS => self.do_set_tid_address(args),
            SYS_SET_ROBUST_LIST => self.do_common("set_robust_list", 2),
            SYS_CLOCK_GETTIME => self.do_common("clock_gettime", 2),
            SYS_UNAME => self.do_uname(args),
            SYS_BRK => self.do_brk(args),
            SYS_MMAP => self.do_mmap(args),
            SYS_MUNMAP => self.do_common("munmap", 2),
            SYS_MPROTECT => self.do_mprotect(args),

            SYS_PRLIMIT64 => self.do_common("prlimit64", 4),
            SYS_GETRANDOM => self.do_common("getrandom", 3),
            SYS_KILL=> self.do_kill(args),
            SYS_RT_SIGACTION => self.do_rt_sigaction(args),
            SYS_RT_SIGPROCMASK => self.do_rt_sigprocmask(args),
            SYS_CLONE => self.do_clone(args),
            SYS_EXECVE => self.do_execve(args),
            SYS_GETTID => self.do_common("get_tid", 0),
            SYS_GETPID => self.do_getpid(args),
            SYS_TGKILL => self.do_common("tgkill", 3),
            SYS_WAIT4 => self.do_wait4(args),
            SYS_GETDENTS64 => self.do_common("getdents64", 3),
            _ => ("", 7, format!("{:#x}", self.result)),
        }
    }

    fn do_brk(&self, _args: &mut Vec<String>) -> (&'static str, usize, String) {
        ("brk", 1, format!("{:#x}", self.result))
    }

    fn do_set_tid_address(&self, _args: &mut Vec<String>) -> (&'static str, usize, String) {
        let result = if self.level == 2 {
            self.mask_tid(self.result)
        } else {
            format!("{:#x}", self.result)
        };
        ("set_tid_address", 1, result)
    }

    fn do_kill(&self, args: &mut Vec<String>) -> (&'static str, usize, String) {
        if self.level == 2 {
            args[0] = self.mask_tid(parse_usize(&args[0]) as i64);
        }
        ("kill", 2, format!("{:#x}", self.result))
    }

    fn do_getpid(&self, _args: &mut Vec<String>) -> (&'static str, usize, String) {
        let result = if self.level == 2 {
            self.mask_tid(self.result)
        } else {
            format!("{:#x}", self.result)
        };
        ("getpid", 0, result)
    }

    fn do_wait4(&self, args: &mut Vec<String>) -> (&'static str, usize, String) {
        let result = if self.level == 2 {
            args[0] = self.mask_tid(parse_usize(&args[0]) as i64);
            self.mask_tid(self.result)
        } else {
            format!("{:#x}", self.result)
        };
        ("wait4", 4, result)
    }

    fn do_clone(&self, _args: &mut Vec<String>) -> (&'static str, usize, String) {
        let result = if self.result != 0 && self.level == 2 {
            self.mask_tid(self.result)
        } else {
            format!("{:#x}", self.result)
        };
        ("clone", 5, result)
    }

    fn mask_tid(&self, oid: i64) -> String {
        let mut tid_map = TID_MAP.lock().unwrap();
        if let Some(tid) = tid_map.get(&oid) {
            tid.clone()
        } else {
            let tid = format!("tid_{}", tid_map.len());
            tid_map.insert(oid, tid.clone());
            tid
        }
    }

    #[inline]
    fn do_common(&self, name: &'static str, argc: usize) -> (&'static str, usize, String) {
        if self.result <= 0 {
            (name, argc, format!("{}", errno_name(self.result)))
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
        if self.level != 2 {
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
        } else {
            format!(
                "{{dev, ino, mode={:#o}, nlink={}, rdev={}, size={}, blksize, blocks={}}}",
                k.st_mode,
                k.st_nlink,
                k.st_rdev,
                k.st_size,
                k.st_blocks
            )
        }
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
            if self.level == 2 && i == 3 {
                names.push("%timestamp%".to_string());
                continue;
            }
            let fname = CStr::from_bytes_until_nul(&utsname.fields[i][..]).unwrap();
            names.push(format!("{:?}", fname));
        }
        let r_uname = names.join(", ");
        args[payload.index] = format!("{{{}}}", r_uname);
        ("uname", 1, format!("{:#x}", self.result))
    }

    fn do_mmap(&self, args: &mut Vec<String>) -> (&'static str, usize, String) {
        if !self.raw_fmt {
            if self.head.ax[0] == 0 {
                args[0] = String::from("NULL");
            }
            args[2] = prot_name(self.head.ax[2]);
            args[3] = map_name(self.head.ax[3]);
            if self.head.ax[4] == u64::MAX {
                args[4] = "-1".to_string();
            }
        }
        if self.result <= 0 {
            ("mmap", 6, String::from("MAP_FAILED")) // On error, the value MAP_FAILED(that is, (void *) -1) is returned,
        } else {
            ("mmap", 6, format!("{:#x}", self.result)) // On success, mmap() returns a pointer to the mapped area.
        }
    }

    fn do_rt_sigaction(&self, args: &mut Vec<String>) -> (&'static str, usize, String) {
        let signum = self.head.ax[0];
        args[0] = sig_name(signum);

        if let Some((sig_action, index)) = parse_sigaction(self) {
            args[index] = sig_action.to_string();
        }
        ("rt_sigaction", 3, format!("{:#x}", self.result))
    }

    fn do_rt_sigprocmask(&self, args: &mut Vec<String>) -> (&'static str, usize, String) {
        args[0] = match self.head.ax[0] {
            SIG_BLOCK => "SIG_BLOCK",
            SIG_UNBLOCK => "SIG_UNBLOCK",
            SIG_SETMASK => "SIG_SETMASK",
            _ => panic!("bad how"),
        }.to_string();

        let mut index = 0;
        if self.head.ax[1] != 0 {
            let payload = self.payloads.get(index).unwrap();
            index += 1;
            let mut buf = [0u8; 8];
            buf.clone_from_slice(&payload.data[..8]);
            let nset = unsafe { mem::transmute::<[u8; 8], u64>(buf) };
            args[1] = format!("nset: {:#x}", nset);
        } else {
            args[1] = format!("nset: NULL");
        }
        if self.head.ax[2] != 0 {
            let payload = self.payloads.get(index).unwrap();
            index += 1;
            let mut buf = [0u8; 8];
            buf.clone_from_slice(&payload.data[..8]);
            let oset = unsafe { mem::transmute::<[u8; 8], u64>(buf) };
            args[2] = format!("oset: {:#x}", oset);
        } else {
            args[2] = format!("oset: NULL");
        }
        assert_eq!(index, self.payloads.len());
        ("rt_sigprocmask", 4, format!("{:#x}", self.result))
    }

    fn do_mprotect(&self,args: &mut Vec<String>) -> (&'static str, usize, String) {
        if self.head.ax[0] == 0 {
            args[0] = String::from("NULL");
        }
        args[2] = prot_name(self.head.ax[2]);
        if self.result <= 0 {
            ("mprotect", 3, format!("{}", errno_name(self.result)))
        } else {
            ("mprotect", 3, format!("{:#x}", self.result))
        }
    }

    fn do_write(&self, args: &mut Vec<String>) -> (&'static str, usize, String) {
        args[0] = format!("{}", self.head.ax[0] as isize); // fd
        if self.head.ax[0] == 1 || self.head.ax[0] == 2 {
            if self.payloads.len() == 1 {
                let payload = &self.payloads.first().unwrap();
                assert_eq!(payload.inout, crate::OUT);
                assert_eq!(payload.index, 1);
                args[payload.index] = match CStr::from_bytes_until_nul(&payload.data) {
                    Ok(content) => {
                        format!("{:?}", content)
                    }
                    Err(_) => "[!parse_str_err!]".to_string(),
                };
            }
        }

        ("write", 3, format!("{:#x}", self.result))
    }

    fn do_read(&self, args: &mut Vec<String>) -> (&'static str, usize, String) {
        args[0] = format!("{}", self.head.ax[0] as isize); // fd
        if self.head.ax[0] == 0 {
            if self.payloads.len() == 1 {
                let payload = &self.payloads.first().unwrap();
                assert_eq!(payload.inout, crate::OUT);
                assert_eq!(payload.index, 1);

                args[payload.index] = match CStr::from_bytes_until_nul(&payload.data) {
                    Ok(content) => {
                        format!("{:?}", content)
                    }
                    Err(_) => "[!parse_str_err!]".to_string(),
                };
            }
        }

        ("read", 3, format!("{:#x}", self.result))
    }

    fn do_execve(&self, args: &mut Vec<String>) -> (&'static str, usize, String) {
        let mut argv = Vec::new();
        let mut envp = Vec::new();
        for payload in &self.payloads {
            if payload.index == 0 {
                args[payload.index] = match CStr::from_bytes_until_nul(&payload.data) {
                    Ok(content) => {
                        format!("{:?}", content)
                    }
                    Err(_) => "[!parse_str_err!]".to_string(),
                };
            }else if payload.index == 1 {
                argv.push(match CStr::from_bytes_until_nul(&payload.data) {
                    Ok(content) => {
                        format!("{:?}", content)
                    }
                    Err(_) => "[!parse_str_err!]".to_string(),
                })
            }else if payload.index == 2 {
                envp.push(match CStr::from_bytes_until_nul(&payload.data) {
                    Ok(content) => {
                        format!("{:?}", content)
                    }
                    Err(_) => "[!parse_str_err!]".to_string(),
                })
            }
        }
        args[1] = format!("{{{}}}", argv.join(", "));
        args[2] = format!("{{{}}}", envp.join(", "));
        ("execve",3, format!("{:#x}", self.result))
    }
}

impl Display for TraceEvent {
    fn fmt(&self, fmt: &mut Formatter) -> std::fmt::Result {
        match self.signal {
            SigStage::Enter(signo) => {
                return write!(fmt, "Signal[{}] enter..", sig_name(signo));
            },
            SigStage::Exit(signo) => {
                writeln!(fmt, "Signal[{}] exit..", sig_name(signo))?;
            },
            _ => (),
        }
        assert_eq!(self.head.cause, USER_ECALL);

        let mut args = self.head.ax[..7]
            .iter()
            .map(|arg| format!("{:#x}", arg))
            .collect::<Vec<_>>();

        let (sysname, argc, result) = self.handle_syscall(&mut args);
        let sysname = if sysname.len() > 0 {
            sysname.to_owned()
        } else {
            format!("sys_{}", self.head.ax[7])
        };

        write!(
            fmt,
            "{}({}) -> {}, usp: {:#x}",
            sysname,
            args[..argc].join(", "),
            result,
            self.head.usp
        )
    }
}

pub fn parse_sigaction(evt: &TraceEvent) -> Option<(SigAction, usize)> {
    let payload = evt.payloads.first()?;
    let mut buf = [0u8; 24];
    buf.clone_from_slice(&payload.data[..24]);
    let sigaction = unsafe { mem::transmute::<[u8; 24], SigAction>(buf) };
    Some((sigaction, payload.index))
}

pub fn print_events(tid: u64, events: &Vec<TraceEvent>) {
    println!("Task[{:#x}] ========>", tid);
    for (idx, evt) in events.iter().enumerate() {
        println!("[{}]: {}", idx, evt);
    }
    println!();
}

pub fn parse_event(reader: &mut BufReader<File>, level: usize) -> Result<TraceEvent> {
    let mut buf = [0u8; TE_SIZE];
    reader.read_exact(&mut buf)?;
    let head = unsafe { mem::transmute::<[u8; TE_SIZE], TraceHead>(buf) };
    assert_eq!(head.cause, USER_ECALL);

    //println!("a7: {} total: {}", head.ax[7], head.totalsize);
    let payloads = if head.totalsize as usize > head.headsize as usize {
        parse_payloads(
            reader,
            head.inout,
            head.totalsize as usize - head.headsize as usize,
        )?
    } else {
        vec![]
    };

    let evt = TraceEvent {
        head,
        result: 0,
        payloads,
        signal: SigStage::Empty,
        raw_fmt: false,
        level: level,
    };
    Ok(evt)
}

fn parse_usize(s: &str) -> usize {
    let s = s.trim();
    assert!(s.starts_with("0x"), "input: {}", s);
    usize::from_str_radix(&s[2..], 16).unwrap()
}
