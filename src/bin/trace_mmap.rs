use std::env;
use std::fs;
use std::fs::File;
use std::io::BufReader;
use std::io::Result;
use std::io::Write;
use std::sync::Arc;
use std::collections::HashMap;
use lkdiff::OUT;
use lkdiff::event::{LK_MAGIC, TE_SIZE, parse_event};
use lkdiff::sysno::{SYS_MMAP, SYS_MUNMAP, SYS_OPENAT, SYS_CLOSE};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!("Usage: lkdiff [trace.data]");
        return;
    }
    let _ = fs::create_dir("/tmp/mmap_cases");

    let rfile = &args[1];
    parse_file(rfile).expect("reference is a bad file.");
}

fn parse_file(fname: &str) -> Result<()> {
    let f = File::open(fname)?;
    let mut filesize = f.metadata().unwrap().len() as usize;
    let mut reader = BufReader::new(f);

    let mut out_map: HashMap<u64, Arc<File>> = HashMap::new();
    while filesize >= TE_SIZE {
        let mut evt = parse_event(&mut reader)?;
        let advance = evt.head.totalsize as usize;
        assert_eq!(evt.head.magic, LK_MAGIC);
        assert_eq!(evt.head.headsize, TE_SIZE as u16);
        assert!(evt.head.totalsize >= evt.head.headsize as u32);
        if evt.head.inout != OUT {
            filesize -= advance;
            continue;
        }

        evt.result = evt.head.ax[0] as i64;
        evt.head.ax[0] = evt.head.orig_a0;

        let mut file = if let Some(f) = out_map.get(&evt.head.satp) {
            f.clone()
        } else {
            let path = format!("/tmp/mmap_cases/{:#x}.flow", evt.head.satp);
            let f = Arc::new(File::create(&path).unwrap());
            out_map.insert(evt.head.satp, f.clone());
            f
        };
        /*
        println!("tid: {:#x} -> ({})[{:#x}, {:#x}, {}]",
            evt.head.sscratch, evt.head.inout,
            evt.head.cause, evt.head.epc, evt.head.ax[7]);
        */

        if evt.head.ax[7] == SYS_MMAP || evt.head.ax[7] == SYS_MUNMAP ||
            evt.head.ax[7] == SYS_OPENAT || evt.head.ax[7] == SYS_CLOSE {
            if evt.head.ax[7] == SYS_MMAP {
                evt.raw_fmt = true;
            }
            let record = format!("{}\n", evt);
            let record = record.replace(r"->", "|");
            let record = record.replace(&['(', ')', ','], "|");
            let _ = file.write_all(record.as_bytes());
        }
        filesize -= advance;
    }

    Ok(())
}
