use std::io::prelude::*;
use std::fs::File;
use std::io::Result;
use std::io::BufReader;
use std::fmt::{Display, Formatter};

mod systable;

fn main() {
    println!("lkdiff: ...");
    let first = "/tmp/qemu.log.lk";
    parse(first).expect("{first} is a bad file.");
    println!("lkdiff: ok!");
}

fn parse(fname: &str) -> Result<()> {
    let f = File::open(fname)?;
    let mut reader = BufReader::new(f);

    let mut line = String::new();
    reader.read_line(&mut line)?;
    assert!(line.starts_with("in: "));
    let evt = Event::parse(&line[4..].trim());
    println!("evt: {}", evt);
    Ok(())
}

struct Event {
    tp: usize,
    epc: usize,
    sysno: usize,
    syscall: String,
    args: Vec<usize>,
    usp: usize,
}

impl Display for Event {
    fn fmt(&self, fmt: &mut Formatter) -> std::fmt::Result {
        write!(fmt, "{}()", self.syscall)
    }
}

impl Event {
    /// Format: tp|epc|sysno(a7)|a0|..|a6
    fn parse(line: &str) -> Self {
        println!("line: {}", line);
        let fields: Vec<_> = line.split('|').map(|item|
            usize::from_str_radix(item, 16).unwrap()
        ).collect();
        println!("parsed: {:?}", &fields[3..10]);

        let sysno = fields[2];
        let syscall = systable::name(sysno);

        Event {
            tp: fields[0],
            epc: fields[1],
            sysno,
            syscall: syscall.to_string(),
            args: fields[3..10].to_vec(),
            usp: 0,
        }
    }
}
