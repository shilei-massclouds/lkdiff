use std::fmt::Display;
use crate::sysno::*;

pub const SIG_BLOCK:    u64 = 0; // for blocking signals
pub const SIG_UNBLOCK:  u64 = 1; // for unblocking signals
pub const SIG_SETMASK:  u64 = 2; // for setting the signal mask

// Note: No restorer in sigaction for riscv64.
#[derive(Copy, Clone, Default)]
pub struct SigAction {
    pub handler: usize,
    pub flags: usize,
    pub mask: usize,
}

#[allow(dead_code)]
pub const NSIG: usize = 64;

/// signal action flags
pub const SA_RESTORER: usize = 0x4000000;
pub const SA_RESTART: usize = 0x10000000;

/*
 * if a blocked call to one of the following interfaces is
 * interrupted by a signal handler, then the call is automatically
 * restarted after the signal handler returns if the SA_RESTART flag
 * was used; otherwise the call fails with the error EINTR:
 */
#[allow(dead_code)]
pub const RESTART_SYSCALLS: [u64;5] = [
    SYS_READ,
    SYS_WRITE,
    SYS_WRITEV,
    SYS_IOCTL,
    SYS_WAIT4,
];

impl Display for SigAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{{ handler: {:#x}, flags: {}, mask: {:#x} }}",
            self.handler,
            sa_flag_name(self.flags),
            self.mask
        )
    }
}

pub fn sa_flag_name(sa_flags: usize) -> String {
    let mut names: Vec<String> = vec![];
    if sa_flags & SA_RESTART != 0 {
        names.push("SA_RESTART".to_string());
    }
    if sa_flags & SA_RESTORER != 0 {
        names.push("SA_RESTORER".to_string());
    }
    if names.len() > 0 {
        names.join("|")
    } else {
        String::from("0x0")
    }
}

pub fn sig_name(signum: u64) -> String {
    match signum {
        1 => "SIGHUP".to_string(),
        2 => "SIGINT".to_string(),
        3 => "SIGQUIT".to_string(),
        4 => "SIGILL".to_string(),
        5 => "SIGTRAP".to_string(),
        6 => "SIGABRT".to_string(),
        7 => "SIGBUS".to_string(),
        8 => "SIGFPE".to_string(),
        9 => "SIGKILL".to_string(),
        10 => "SIGUSR1".to_string(),
        11 => "SIGSEGV".to_string(),
        12 => "SIGUSR2".to_string(),
        13 => "SIGPIPE".to_string(),
        14 => "SIGALRM".to_string(),
        15 => "SIGTERM".to_string(),
        16 => "SIGSTKFLT".to_string(),
        17 => "SIGCHLD".to_string(),
        18 => "SIGCONT".to_string(),
        19 => "SIGSTOP".to_string(),
        20 => "SIGTSTP".to_string(),
        21 => "SIGTTIN".to_string(),
        22 => "SIGTTOU".to_string(),
        23 => "SIGURG".to_string(),
        24 => "SIGXCPU".to_string(),
        25 => "SIGXFSZ".to_string(),
        26 => "SIGVTALRM".to_string(),
        27 => "SIGPROF".to_string(),
        28 => "SIGWINCH".to_string(),
        29 => "SIGIO".to_string(),
        30 => "SIGPWR".to_string(),
        31 => "SIGSYS".to_string(),
        34 => "SIGRTMIN".to_string(),
        35 => "SIGRTMIN+1".to_string(),
        36 => "SIGRTMIN+2".to_string(),
        37 => "SIGRTMIN+3".to_string(),
        38 => "SIGRTMIN+4".to_string(),
        39 => "SIGRTMIN+5".to_string(),
        40 => "SIGRTMIN+6".to_string(),
        41 => "SIGRTMIN+7".to_string(),
        42 => "SIGRTMIN+8".to_string(),
        43 => "SIGRTMIN+9".to_string(),
        44 => "SIGRTMIN+10".to_string(),
        45 => "SIGRTMIN+11".to_string(),
        46 => "SIGRTMIN+12".to_string(),
        47 => "SIGRTMIN+13".to_string(),
        48 => "SIGRTMIN+14".to_string(),
        49 => "SIGRTMIN+15".to_string(),
        50 => "SIGRTMAX-14".to_string(),
        51 => "SIGRTMAX-13".to_string(),
        52 => "SIGRTMAX-12".to_string(),
        53 => "SIGRTMAX-11".to_string(),
        54 => "SIGRTMAX-10".to_string(),
        55 => "SIGRTMAX-9".to_string(),
        56 => "SIGRTMAX-8".to_string(),
        57 => "SIGRTMAX-7".to_string(),
        58 => "SIGRTMAX-6".to_string(),
        59 => "SIGRTMAX-5".to_string(),
        60 => "SIGRTMAX-4".to_string(),
        61 => "SIGRTMAX-3".to_string(),
        62 => "SIGRTMAX-2".to_string(),
        63 => "SIGRTMAX-1".to_string(),
        64 => "SIGRTMAX".to_string(),
        _ => "SIGUNKNOWN".to_string(),
    }
}
