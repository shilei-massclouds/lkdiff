//! Query syscall name based on sysno

pub fn name(sysno: usize) -> &'static str {
    match sysno {
        0xd6 => "brk",
        _ => "[unknown sysno]",
    }
}
