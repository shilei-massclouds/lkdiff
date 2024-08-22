//! Linux errno

/// Operation not permitted
pub const EPERM:  i32 = 1;
/// No such file or directory
pub const ENOENT: i32 = 2;
/// No child processes
pub const ECHILD: i32 = 10;
/// Not a directory
pub const ENOTDIR:i32 = 20;
/// Is a directory
pub const EISDIR: i32 = 21;
/// Invalid argument
pub const EINVAL: i32 = 22;
/// Not a typewriter
pub const ENOTTY: i32 = 25;

pub fn errno_name(err: i64) -> &'static str {
    let err = err as i32;
    match -err {
        0 => "OK",
        EPERM => "EPERM",
        ENOENT => "ENOENT",
        ECHILD => "ECHILD",
        ENOTDIR => "ENOTDIR",
        EISDIR => "EISDIR",
        EINVAL => "EINVAL",
        ENOTTY => "ENOTTY",
        _ => {
            println!("Unknown errno: {}", -err);
            "Unknown errno"
        },
    }
}
