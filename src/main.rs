use std::io::prelude::*;
use std::fs::File;
use std::io::Result;
use std::io::BufReader;
use std::mem;
use std::env;
use event::{TraceHead, TracePayload, TraceEvent, USER_ECALL};

mod event;
mod errno;
mod mmap;

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
    while filesize >= TE_SIZE {
        let mut evt = parse_event(&mut reader)?;
        let advance = evt.head.totalsize as usize;
        assert_eq!(evt.head.magic, LK_MAGIC);
        assert_eq!(evt.head.headsize, TE_SIZE as u16);
        assert!(evt.head.totalsize >= evt.head.headsize as u32);
        //println!("{}: [{:#x}, {:#x}, {:#x}]", evt.inout, evt.cause, evt.epc, evt.ax[7]);
        if wait_reply {
            assert!(wait_reply);
            wait_reply = false;

            assert_eq!(evt.head.cause, USER_ECALL);
            assert_eq!(evt.head.inout, OUT);
            let last: &mut TraceEvent = events.last_mut().expect("No requests in event queue!");
            assert_eq!(evt.head.epc, last.head.epc + 4);
            assert_eq!(evt.head.ax[7], last.head.ax[7]);
            last.result = evt.head.ax[0];
            last.payloads.append(&mut evt.payloads);
            //println!("replay: {}", last);
            println!("{}", last);
        } else if evt.head.cause == USER_ECALL && evt.head.inout == IN {
            assert_eq!(wait_reply, false);
            wait_reply = true;

            //println!("request: {}", evt.head.ax[7]);
            events.push(evt);
        } else {
            panic!("irq: {}", evt.head.ax[7]);
        }

        filesize -= advance;
    }
    Ok(())
}

fn parse_event(reader: &mut BufReader<File>) -> Result<TraceEvent> {
    let mut buf = [0u8; TE_SIZE];
    reader.read_exact(&mut buf)?;
    let head = unsafe {
        mem::transmute::<[u8; TE_SIZE], TraceHead>(buf)
    };

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
