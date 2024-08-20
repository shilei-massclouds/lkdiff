//! Linux errno

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

pub fn errno_name(err: i64) -> &'static str {
    let err = err as i32;
    match -err {
        0 => "OK",
        ENOENT => "ENOENT",
        ECHILD => "ECHILD", 
        ENOTDIR => "ENOTDIR", 
        EISDIR => "EISDIR", 
        EINVAL => "EINVAL", 
        _ => {
            println!("Unknown errno: {}", -err);
            "Unknown errno"
        },
    }
}
