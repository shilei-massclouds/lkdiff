mod errno;
pub mod event;
mod payload;
mod mmap;
#[allow(unused)]
pub mod sysno;
mod signal;

pub const IN: u64 = 0;
pub const OUT: u64 = 1;
