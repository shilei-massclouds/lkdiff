

// mmap const
pub const PROT_READ: u64 = 0x1;
pub const PROT_WRITE: u64 = 0x2;
pub const PROT_EXEC: u64 = 0x4;
pub const PROT_SEM: u64 = 0x8;
pub const PROT_NONE: u64 = 0x0;
pub const PROT_GROWSDOWN: u64 = 0x01000000;
pub const PROT_GROWSUP: u64 = 0x02000000;

/// Share changes
pub const MAP_SHARED: u64 = 0x01;
/// Changes are private
pub const MAP_PRIVATE: u64 = 0x02;
/// share + validate extension flags
const MAP_SHARED_VALIDATE: u64 = 0x03;

/// Interpret addr exactly.
pub const MAP_FIXED: u64 = 0x10;
/// Don't use a file.
pub const MAP_ANONYMOUS: u64 = 0x20;

/// stack-like segment
const MAP_GROWSDOWN: u64 = 0x0100;
/// ETXTBSY
const MAP_DENYWRITE: u64 = 0x0800;
/// mark it as an executable */
const MAP_EXECUTABLE: u64= 0x1000;
/// pages are locked */
const MAP_LOCKED: u64    = 0x2000;
/// don't check for reservations */
const MAP_NORESERVE: u64 = 0x4000;

/// generate prot name
pub fn prot_name(prot:u64) -> String {
    if prot == PROT_NONE {
        return String::from("PROT_NONE");
    }
    let mut names : Vec<String> = vec![];
    if prot & PROT_READ != 0 {
        names.push("PROT_READ".to_string());
    }
    if prot & PROT_WRITE != 0 {
        names.push("PROT_WRITE".to_string());
    }
    if prot & PROT_EXEC != 0 {
        names.push("PROT_EXEC".to_string());
    }
    if prot & PROT_SEM != 0 {
        names.push("PROT_SEM".to_string());
    }
    if prot & PROT_GROWSDOWN != 0 {
        names.push("PROT_GROWSDOWN".to_string());
    }
    if prot & PROT_GROWSUP != 0 {
        names.push("PROT_GROWSUP".to_string());
    }
    names.join("|")
}

pub fn map_name(map:u64) -> String {
    let mut names : Vec<String> = vec![];
    match map & 3 {
        MAP_SHARED_VALIDATE => names.push("MAP_SHARED_VALIDATE".to_string()),
        MAP_SHARED => names.push("MAP_SHARED".to_string()),
        MAP_PRIVATE => names.push("MAP_PRIVATE".to_string()),
        _ => names.push("MAP_UNKNOWN".to_string()),
    }

    if map & MAP_FIXED != 0 {
        names.push("MAP_FIXED".to_string());
    }
    if map & MAP_ANONYMOUS != 0 {
        names.push("MAP_ANONYMOUS".to_string());
    }
    if map & MAP_GROWSDOWN != 0 {
        names.push("MAP_GROWSDOWN".to_string());
    }
    if map & MAP_DENYWRITE != 0 {
        names.push("MAP_DENYWRITE".to_string());
    }
    if map & MAP_EXECUTABLE != 0 {
        names.push("MAP_EXECUTABLE".to_string());
    }
    if map & MAP_LOCKED != 0 {
        names.push("MAP_LOCKED".to_string());
    }
    if map & MAP_NORESERVE != 0 {
        names.push("MAP_NORESERVE".to_string());
    }
    names.join("|")
}
