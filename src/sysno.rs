///
/// Linux syscall
///

/*
pub const SYS_GETCWD: u64 = 0x11;
pub const SYS_FCNTL: u64 = 0x19;
pub const SYS_IOCTL: u64 = 0x1d;
pub const SYS_MKDIRAT: u64 = 0x22;
pub const SYS_UNLINKAT: u64 = 0x23;
pub const SYS_FTRUNCATE: u64 = 0x2e;
pub const SYS_FACCESSAT: u64 = 0x30;
pub const SYS_CHDIR: u64 = 0x31;
pub const SYS_FCHMOD: u64 = 0x34;
pub const SYS_FCHMODAT: u64 = 0x35;
pub const SYS_FCHOWNAT: u64 = 0x36;
pub const SYS_OPENAT: u64 = 0x38;
pub const SYS_CLOSE: u64 = 0x39;
pub const SYS_GETDENTS64: u64 = 0x3d;
pub const SYS_LSEEK: u64 = 0x3e;
pub const SYS_READ: u64 = 0x3f;
pub const SYS_PREAD64: u64 = 67;
pub const SYS_WRITE: u64 = 0x40;
pub const SYS_WRITEV: u64 = 0x42;
pub const SYS_READLINKAT: u64 = 0x4e;
pub const SYS_FSTATAT: u64 = 0x4f;
pub const SYS_CAPGET: u64 = 0x5a;
pub const SYS_EXIT: u64 = 0x5d;
*/
pub const SYS_EXIT_GROUP: u64 = 0x5e;
/*
pub const SYS_SETITIMER: u64 = 0x67;
pub const SYS_TGKILL: u64 = 0x83;
*/
pub const SYS_KILL: u64 = 0x81;
pub const SYS_RT_SIGACTION: u64 = 0x86;
pub const SYS_RT_SIGPROCMASK: u64 = 0x87;
pub const SYS_RT_SIGRETURN: u64 = 0x8b;
/*
pub const SYS_SETPGID: u64 = 0x9a;
pub const SYS_UNAME: u64 = 0xa0;
pub const SYS_GETPID: u64 = 0xac;
pub const SYS_GETPPID: u64 = 0xad;
pub const SYS_GETUID: u64 = 0xae;
pub const SYS_GETEUID: u64 = 0xaf;
pub const SYS_GETGID: u64 = 0xb0;
pub const SYS_GETEGID: u64 = 0xb1;
pub const SYS_GETTID: u64 = 0xb2;
pub const SYS_BRK: u64 = 0xd6;
pub const SYS_MUNMAP: u64 = 0xd7;
*/
pub const SYS_CLONE: u64 = 0xdc;
pub const SYS_EXECVE: u64 = 0xdd;
/*
pub const SYS_MMAP: u64 = 0xde;
pub const SYS_MPROTECT: u64 = 0xe2;
pub const SYS_MSYNC: u64 = 0xe3;
pub const SYS_MADVISE: u64 = 0xe9;
*/
pub const SYS_WAIT4: u64 = 0x104;
/*
pub const SYS_PRLIMIT64: u64 = 0x105;
pub const SYS_GETRANDOM: u64 = 0x116;
pub const SYS_RSEQ: u64 = 0x125;

pub const SYS_SET_TID_ADDRESS: u64 = 0x60;
pub const SYS_SET_ROBUST_LIST: u64 = 0x63;
pub const SYS_CLOCK_GETTIME: u64 = 0x71;
pub const SYS_CLOCK_NANOSLEEP: u64 = 0x73;
pub const SYS_SCHED_GETAFFINITY: u64 = 0x7b;
*/
