use std::io::prelude::*;
use std::fs::File;
use std::io::Result;
use std::io::BufReader;
use std::fmt::{Display, Formatter};

mod systable;

fn main() {
    println!("lkdiff: ...");
    let first = "/tmp/linux.log";
    parse(first).expect("refer-file is a bad file.");
    println!("lkdiff: ok!");
}

const IN: usize = 0;
const OUT: usize = 1;
const USER_ECALL: usize = 8;

fn parse(fname: &str) -> Result<()> {
    let f = File::open(fname)?;
    let mut reader = BufReader::new(f);

    let mut events = vec![];
    let mut line = String::new();
    let mut wait_reply = false;
    while reader.read_line(&mut line)? != 0 {
        let evt = Event::parse(line.trim());
        println!("evt: {}", evt);
        if wait_reply {
            assert_eq!(evt.inout, OUT);
            let last: &Event = events.last().expect("No requests in event queue!");
            assert_eq!(evt.epc, last.epc + 4);
            assert_eq!(wait_reply, true);
            wait_reply = false;
        } else if evt.cause == USER_ECALL && evt.inout == IN {
            events.push(evt);
            assert_eq!(wait_reply, false);
            wait_reply = true;
        }
        line.clear();
    }
    Ok(())
}

struct Event {
    inout: usize,
    cause: usize,
    epc: usize,
    sysno: usize,
    syscall: String,
    args: Vec<usize>,
    usp: usize,
}

impl Display for Event {
    fn fmt(&self, fmt: &mut Formatter) -> std::fmt::Result {
        let args = self.args.iter().map(|item|
            format!("{:#x}", item)
        ).collect::<Vec<_>>().join(", ");

        write!(fmt, "[{}]{}({}), usp: {:#x}",
            self.sysno, self.syscall, args, self.usp)
    }
}

impl Event {
    /// Format: [0|1]|cause|epc|sysno(a7)|a0|..|a6
    fn parse(line: &str) -> Self {
        //println!("line: {}", line);
        let fields: Vec<_> = line.split('|').map(|item|
            usize::from_str_radix(item, 16).unwrap()
        ).collect();
        //println!("parsed: {:?}", &fields[2..9]);

        let cause = fields[1];
        let sysno = fields[3];
        let syscall = if cause == USER_ECALL {
            systable::name(sysno)
        } else {
            "irq"
        };

        Event {
            inout: fields[0],
            cause: cause,
            epc: fields[2],
            sysno,
            syscall: syscall.to_string(),
            args: fields[4..11].to_vec(),
            usp: 0,
        }
    }
}
