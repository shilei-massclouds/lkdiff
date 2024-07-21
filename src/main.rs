use std::io::prelude::*;
use std::fs::File;
use std::io::Result;
use std::io::BufReader;
use std::mem;
use std::env;
use event::{TraceHead, TracePayload, TraceEvent, USER_ECALL};
use sysno::*;

mod event;
mod errno;
mod sysno;

const IN: u64 = 0;
const OUT: u64 = 1;

const LK_MAGIC: u16 = 0xABCD;
const TE_SIZE: usize = mem::size_of::<TraceHead>();
const PH_SIZE: usize = mem::size_of::<PayloadHead>();

#[repr(C)]
struct PayloadHead {
    magic: u16,
    index: u16,
    size: u32,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!("Usage: lkdiff [trace.data]");
        return;
    }
    let rfile = &args[1];
    parse_file(rfile).expect("reference is a bad file.");
}

fn parse_file(fname: &str) -> Result<()> {
    let f = File::open(fname)?;
    let mut filesize = f.metadata().unwrap().len() as usize;
    let mut reader = BufReader::new(f);

    let mut wait_reply = false;
    let mut events = vec![];
    let mut vfork_req = None;
    while filesize >= TE_SIZE {
        let mut evt = parse_event(&mut reader)?;
        let advance = evt.head.totalsize as usize;
        assert_eq!(evt.head.magic, LK_MAGIC);
        assert_eq!(evt.head.headsize, TE_SIZE as u16);
        assert!(evt.head.totalsize >= evt.head.headsize as u32);
        println!("{}: [{:#x}, {:#x}, {:#x}]", evt.head.inout, evt.head.cause, evt.head.epc, evt.head.ax[7]);
        assert_eq!(evt.head.cause, USER_ECALL);
        if wait_reply {
            wait_reply = false;

            assert_eq!(evt.head.inout, OUT);
            let last: &mut TraceEvent = events.last_mut().expect("No requests in event queue!");
            assert_eq!(evt.head.ax[7], last.head.ax[7]);
            if evt.head.ax[7] != SYS_EXECVE {
                assert_eq!(evt.head.epc, last.head.epc + 4);
            }
            last.result = evt.head.ax[0];
            last.payloads.append(&mut evt.payloads);
            //println!("replay: {}", last);
        } else if evt.head.inout == IN {
            assert_eq!(wait_reply, false);
            let sysno = evt.head.ax[7];
            if sysno != SYS_EXIT_GROUP {
                wait_reply = true;
            }

            if sysno == SYS_CLONE {
                vfork_req = Some(evt.clone());
            }
            //println!("request: {}", evt.head.ax[7]);
            events.push(evt);
        } else if evt.head.inout == OUT {
            // Special case: sysno must be clone(vfork)
            assert_eq!(evt.head.ax[7], SYS_CLONE);
            if let Some(last) = vfork_req {
                assert_eq!(last.head.ax[7], SYS_CLONE);
                assert_eq!(last.payloads.len(), 0);
                assert_eq!(evt.head.epc, last.head.epc + 4);
                evt.result = evt.head.ax[0];
                evt.head.ax[0] = last.head.ax[0];
            } else {
                panic!("bad vfork request {:?}", vfork_req);
            }
            vfork_req = None;
            events.push(evt);
        } else {
            panic!("irq: {}", evt.head.ax[7]);
        }

        filesize -= advance;
    }

    for evt in events {
        println!("{}", evt);
    }
    Ok(())
}

fn parse_event(reader: &mut BufReader<File>) -> Result<TraceEvent> {
    let mut buf = [0u8; TE_SIZE];
    reader.read_exact(&mut buf)?;
    let head = unsafe {
        mem::transmute::<[u8; TE_SIZE], TraceHead>(buf)
    };
    assert_eq!(head.cause, USER_ECALL);

    //println!("a7: {} total: {}", head.ax[7], head.totalsize);
    let payloads = if head.totalsize as usize > head.headsize as usize {
        parse_payloads(reader, head.inout, head.totalsize as usize - head.headsize as usize)?
    } else {
        vec![]
    };

    let evt = TraceEvent {
        head,
        result: 0,
        payloads,
    };
    Ok(evt)
}

fn parse_payloads(reader: &mut BufReader<File>, inout: u64, mut size: usize) -> Result<Vec<TracePayload>> {
    assert_eq!(inout, OUT);
    assert!(size > PH_SIZE);
    let mut ret = vec![];
    while size > 0 {
        let payload = parse_payload(reader, inout)?;
        size -= PH_SIZE + payload.data.len();
        ret.push(payload);
    }
    Ok(ret)
}

fn parse_payload(reader: &mut BufReader<File>, inout: u64) -> Result<TracePayload> {
    let mut buf = [0u8; PH_SIZE];
    reader.read_exact(&mut buf)?;
    let head = unsafe {
        mem::transmute::<[u8; PH_SIZE], PayloadHead>(buf)
    };
    let mut data = Vec::with_capacity(head.size as usize);
    unsafe { data.set_len(head.size as usize); }
    reader.read_exact(&mut data)?;

    Ok(TracePayload {
        inout: inout,
        index: head.index as usize,
        data,
    })
}
