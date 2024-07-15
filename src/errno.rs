//! Linux errno

/// No such file or directory
pub const ENOENT: i32 = 2;

pub fn errno_name(err: i32) -> &'static str {
    match -err {
        ENOENT => "ENOENT",
        _ => "Unknown errno",
    }
}
