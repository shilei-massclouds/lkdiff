///
/// File System
///
use std::fmt::Display;

#[repr(C)]
pub struct FileSystemInfo {
    /// Type of filesystem
    f_type: u64,
    /// Optimal transfer block size
    f_bsize: u64,
    /// Total data blocks in filesystem
    f_blocks: u64,
    /// Free blocks in filesystem
    f_bfree: u64,
    /// Free blocks available to unprivileged user
    f_bavail: u64,
    /// Total inodes in filesystem
    f_files: u64,
    /// Free inodes in filesystem
    f_ffree: u64,
    /// Filesystem ID
    f_fsid: KernelFsid,
    /// Maximum length of filenames
    f_namelen: u64,
    /// Fragment size (since Linux 2.6)
    f_frsize: u64,
    /// Mount flags of filesystem (since Linux 2.6.36)
    f_flags: u64,
    /// Padding bytes reserved for future use
    f_spare: [u64; 4],
}

#[derive(Debug, Clone, Copy)]
pub struct KernelFsid {
    val: [i32; 2],
}


impl Display for FileSystemInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, 
            "FileSystemInfo {{ f_type: {}, f_bsize: {:x}, f_blocks: {:x}, f_bfree: {:x}, f_bavail: {:x}, f_files: {:x}, f_ffree: {:x}, f_fsid: {}, f_namelen: {}, f_frsize: {}, f_flags: {}, f_spare: {:?} }}", 
            f_type_name(self.f_type), 
            self.f_bsize,
            self.f_blocks,
            self.f_bfree,
            self.f_bavail,
            self.f_files,
            self.f_ffree,
            self.f_fsid,
            self.f_namelen,
            self.f_frsize,
            f_flags_name(self.f_flags),
            self.f_spare,
        )
    }
}

impl Display for KernelFsid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, 
            "KernelFsid {{ val: {:?} }}", 
            self.val)
    }
}

// f_type
const EXT_SUPER_MAGIC:u64 = 0x137d;     /* Linux 2.0 and earlier */
const EXT2_OLD_SUPER_MAGIC:u64=  0xef51;
const EXT2_OR_EXT3_OR_EXT4_SUPER_MAGIC :u64= 0xef53;

fn f_type_name(f_type: u64) -> String {
    match f_type {
        EXT_SUPER_MAGIC => "ext".to_string(),
        EXT2_OLD_SUPER_MAGIC => "ext2".to_string(),
        EXT2_OR_EXT3_OR_EXT4_SUPER_MAGIC => "ext2|ext3|ext4".to_string(),
        _ => format!("{:X}",f_type)
    }
}

// f_flags
const ST_RDONLY :u64 = 0x0001;	/* mount read-only */
const ST_NOSUID	:u64 = 0x0002;	/* ignore suid and sgid bits */
const ST_NODEV	:u64 = 0x0004;	/* disallow access to device special files */
const ST_NOEXEC	:u64 = 0x0008;	/* disallow program execution */
const ST_SYNCHRONOUS	:u64 = 0x0010;	/* writes are synced at once */
const ST_VALID	:u64 = 0x0020;	/* f_flags support is implemented */
const ST_MANDLOCK	:u64 = 0x0040;	/* allow mandatory locks on an FS */
const ST_NOATIME	:u64 = 0x0400;	/* do not update access times */
const ST_NODIRATIME	:u64 = 0x0800;	/* do not update directory access times */
const ST_RELATIME	:u64 = 0x1000;	/* update atime relative to mtime/ctime */
const ST_NOSYMFOLLOW	:u64 = 0x2000;	/* do not follow symlinks */

fn f_flags_name(f_flags:u64) -> String {
    let mut names : Vec<String> = vec![];
    if f_flags & ST_RDONLY != 0 {
        names.push("ST_RDONLY".to_string());
    }
    if f_flags & ST_NOSUID != 0 {
        names.push("ST_NOSUID".to_string());
    }
    if f_flags & ST_NODEV != 0 {
        names.push("ST_NODEV".to_string());
    }
    if f_flags & ST_NOEXEC != 0 {
        names.push("ST_NOEXEC".to_string());
    }
    if f_flags & ST_SYNCHRONOUS != 0 {
        names.push("ST_SYNCHRONOUS".to_string());
    }
    if f_flags & ST_VALID != 0 {
        names.push("ST_VALID".to_string());
    }
    if f_flags & ST_MANDLOCK != 0 {
        names.push("ST_MANDLOCK".to_string());
    }
    if f_flags & ST_NOATIME != 0 {
        names.push("ST_NOATIME".to_string());
    }
    if f_flags & ST_NODIRATIME != 0 {
        names.push("ST_NODIRATIME".to_string());
    }
    if f_flags & ST_RELATIME != 0 {
        names.push("ST_RELATIME".to_string());
    }
    if f_flags & ST_NOSYMFOLLOW != 0 {
        names.push("ST_NOSYMFOLLOW".to_string());
    }
    names.join("|")
}

bitflags::bitflags! {
    /// Node (file/directory) permission mode.
    #[derive(Debug, Clone, Copy)]
    pub struct VfsNodePerm: u16 {
        /// Owner has read permission.
        const OWNER_READ = 0o400;
        /// Owner has write permission.
        const OWNER_WRITE = 0o200;
        /// Owner has execute permission.
        const OWNER_EXEC = 0o100;

        /// Group has read permission.
        const GROUP_READ = 0o40;
        /// Group has write permission.
        const GROUP_WRITE = 0o20;
        /// Group has execute permission.
        const GROUP_EXEC = 0o10;

        /// Others have read permission.
        const OTHER_READ = 0o4;
        /// Others have write permission.
        const OTHER_WRITE = 0o2;
        /// Others have execute permission.
        const OTHER_EXEC = 0o1;
    }
}

impl VfsNodePerm {
    pub const fn rwx_buf(&self) -> [u8; 9] {
        let mut perm = [b'-'; 9];
        if self.contains(Self::OWNER_READ) {
            perm[0] = b'r';
        }
        if self.contains(Self::OWNER_WRITE) {
            perm[1] = b'w';
        }
        if self.contains(Self::OWNER_EXEC) {
            perm[2] = b'x';
        }
        if self.contains(Self::GROUP_READ) {
            perm[3] = b'r';
        }
        if self.contains(Self::GROUP_WRITE) {
            perm[4] = b'w';
        }
        if self.contains(Self::GROUP_EXEC) {
            perm[5] = b'x';
        }
        if self.contains(Self::OTHER_READ) {
            perm[6] = b'r';
        }
        if self.contains(Self::OTHER_WRITE) {
            perm[7] = b'w';
        }
        if self.contains(Self::OTHER_EXEC) {
            perm[8] = b'x';
        }
        perm
    }
}

pub fn mode_name(mode: u64) -> String {
    let node_type = match mode >> 12 {
        0o1 => "FIFO",
        0o2 => "CharDevice",
        0o4 => "Dir",
        0o6 => "BlockDevice",
        0o10 => "File",
        0o12 => "SymLink",
        0o14 => "Socket",
        _ => "Unknown",
    }.to_string();
    format!("\"{} {}\"", node_type,std::str::from_utf8(&VfsNodePerm::from_bits_truncate((mode & 0o777) as u16).rwx_buf()).unwrap())
}

pub const O_ACCMODE:    i32 = 0o003;
pub const O_RDONLY:     i32 = 0o000;
pub const O_WRONLY:     i32 = 0o001;
pub const O_RDWR:       i32 = 0o002;
pub const O_CREAT:      i32 = 0o100;
pub const O_TRUNC:      i32 = 0o001000;
pub const O_APPEND:     i32 = 0o002000;
pub const O_DIRECTORY:  i32 = 0o200000; /* must be a directory */

pub fn open_flags_name(flags: i32) -> String {
    let mut names : Vec<String> = vec![];
    if flags & O_ACCMODE == O_RDONLY {
        names.push("O_RDONLY".to_string());
    }
    if flags & O_ACCMODE == O_WRONLY {
        names.push("O_WRONLY".to_string());
    }
    if flags & O_ACCMODE == O_RDWR {
        names.push("O_RDWR".to_string());
    }
    if flags & O_CREAT != 0 {
        names.push("O_CREAT".to_string());
    }
    if flags & O_TRUNC != 0 {
        names.push("O_TRUNC".to_string());
    }
    if flags & O_APPEND != 0 {
        names.push("O_APPEND".to_string());
    }
    if flags & O_DIRECTORY != 0 {
        names.push("O_DIRECTORY".to_string());
    }
    names.join("|")
}