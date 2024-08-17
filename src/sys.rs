use std::fmt::Display;

pub const RLIMIT_STACK: u64 = 3; /* max stack size */
pub const RLIMIT_NOFILE: u64 = 7; /* max number of open files */

#[repr(C)]
pub struct RLimit64 {
    rlim_cur: u64,
    rlim_max: u64,
}

impl Display for RLimit64 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RLimit64 {{cur:{:x} max:{:x}}}", self.rlim_cur, self.rlim_max)
    }
}