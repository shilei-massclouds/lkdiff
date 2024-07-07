//! Query syscall name based on sysno

pub fn name(sysno: usize) -> &'static str {
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
