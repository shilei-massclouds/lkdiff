use std::io::prelude::*;
use std::fs::File;
use std::io::Result;
use std::io::BufReader;
use std::mem;
use event::{TraceHead, TracePayload, TraceEvent, USER_ECALL};

mod event;

const REFERENCE: &str = "/tmp/lk_trace.data";

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
    parse_file(REFERENCE).expect("reference is a bad file.");
}

fn parse_file(fname: &str) -> Result<()> {
    let f = File::open(fname)?;
    let mut filesize = f.metadata().unwrap().len() as usize;
    let mut reader = BufReader::new(f);

    let mut wait_reply = false;
    let mut events = vec![];
    while filesize >= TE_SIZE {
        let evt = parse_event(&mut reader)?;
        let advance = evt.head.totalsize as usize;
        assert_eq!(evt.head.magic, LK_MAGIC);
        assert_eq!(evt.head.headsize, TE_SIZE as u16);
        assert!(evt.head.totalsize >= evt.head.headsize as u32);
        //println!("{}: [{:#x}, {:#x}, {:#x}]", evt.inout, evt.cause, evt.epc, evt.ax[7]);
        if wait_reply {
            assert_eq!(wait_reply, true);
            wait_reply = false;

            assert_eq!(evt.head.inout, OUT);
            let last: &mut TraceEvent = events.last_mut().expect("No requests in event queue!");
            assert_eq!(evt.head.epc, last.head.epc + 4);
            assert_eq!(evt.head.ax[7], last.head.ax[7]);
            last.result = evt.head.ax[0];
            println!("{}", last);
        } else if evt.head.cause == USER_ECALL && evt.head.inout == IN {
            assert_eq!(wait_reply, false);
            wait_reply = true;

            events.push(evt);
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

    let payloads = if head.totalsize as usize > head.headsize as usize {
        parse_payloads(reader, head.totalsize as usize - head.headsize as usize)?
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

fn parse_payloads(reader: &mut BufReader<File>, size: usize) -> Result<Vec<TracePayload>> {
    assert!(size > PH_SIZE);
    let mut buf = [0u8; PH_SIZE];
    reader.read_exact(&mut buf)?;
    let head = unsafe {
        mem::transmute::<[u8; PH_SIZE], PayloadHead>(buf)
    };
    let mut data = Vec::with_capacity(size - PH_SIZE);
    unsafe { data.set_len(size - PH_SIZE); }
    reader.read_exact(&mut data)?;
    /*
    panic!("maigc {:#x} index {} size {}, data {:?}",
           head.magic, head.index, head.size, data);
           */

    let payload = TracePayload {
        index: head.index as usize,
        data,
    };
    Ok(vec![payload])
}
