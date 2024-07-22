use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::io::Result;
use std::mem;
use std::collections::BTreeMap;
use event::{TraceHead, TracePayload, TraceEvent, USER_ECALL};
use sysno::*;
use event::SigStage;

mod errno;
mod event;
mod mmap;
#[allow(unused)]
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

    let mut events_map: BTreeMap<u64, Vec<TraceEvent>> = BTreeMap::new();
    let mut vfork_req = None;
    let mut saved_req = None;
    while filesize >= TE_SIZE {
        let mut evt = parse_event(&mut reader)?;
        let advance = evt.head.totalsize as usize;
        assert_eq!(evt.head.magic, LK_MAGIC);
        assert_eq!(evt.head.headsize, TE_SIZE as u16);
        assert!(evt.head.totalsize >= evt.head.headsize as u32);
        /*
        println!("tid: {:#x} -> ({})[{:#x}, {:#x}, {:#x}]",
            evt.head.sscratch, evt.head.inout, evt.head.cause, evt.head.epc, evt.head.ax[7]);
            */
        assert_eq!(evt.head.cause, USER_ECALL);

        let tid = evt.head.sscratch;
        let events = match events_map.get_mut(&tid) {
            Some(q) => q,
            None => {
                // Start of each event is either req or clone.replay
                assert!(evt.head.inout == IN || evt.head.ax[7] == SYS_CLONE);
                println!("New events: {:#x}", tid);
                events_map.insert(tid, vec![]);
                let events = events_map.get_mut(&tid).unwrap();
                if evt.head.inout == OUT {
                    let req = vfork_req.take().unwrap();
                    events.push(req);
                }
                events
            },
        };

        match evt.head.inout {
            IN => {
                //println!("request: {}", evt.head.ax[7]);
                if let Some(last) = events.last() {
                    assert_eq!(last.head.inout, OUT);
                }

                let sysno = evt.head.ax[7];
                match sysno {
                    SYS_CLONE => {
                        vfork_req = Some(evt.clone());
                        events.push(evt);
                    },
                    SYS_RT_SIGRETURN => {
                        events.push(saved_req.take().unwrap());
                    },
                    _ => {
                        events.push(evt);
                    },
                }
            },
            OUT => {
                let last = events.last_mut().expect("No requests in event queue!");
                assert_eq!(evt.head.ax[7], last.head.ax[7]);
                if evt.head.epc != last.head.epc + 4 {
                    //println!("signal: evt {:?}", evt);
                    let mut last = events.pop().unwrap();
                    last.signal = SigStage::Exit;
                    saved_req = Some(last);

                    let mut sig_req = TraceEvent::default();
                    sig_req.signal = SigStage::Enter;
                    sig_req.head.inout = OUT;
                    sig_req.head.ax[0] = evt.head.ax[0];
                    events.push(sig_req);
                } else {
                    last.result = evt.head.ax[0];
                    last.payloads.append(&mut evt.payloads);
                    last.head.inout = OUT;
                }
                //println!("replay: {}", last);
            },
            _ => unreachable!(),
        }

        filesize -= advance;
    }

    for (id, events) in events_map.iter() {
        println!("Task[{:#x}] ========>", id);
        for evt in events {
            println!("{}", evt);
        }
        println!();
    }
    Ok(())
}

fn parse_event(reader: &mut BufReader<File>) -> Result<TraceEvent> {
    let mut buf = [0u8; TE_SIZE];
    reader.read_exact(&mut buf)?;
    let head = unsafe { mem::transmute::<[u8; TE_SIZE], TraceHead>(buf) };
    assert_eq!(head.cause, USER_ECALL);

    //println!("a7: {} total: {}", head.ax[7], head.totalsize);
    let payloads = if head.totalsize as usize > head.headsize as usize {
        parse_payloads(
            reader,
            head.inout,
            head.totalsize as usize - head.headsize as usize,
        )?
    } else {
        vec![]
    };

    let evt = TraceEvent {
        head,
        result: 0,
        payloads,
        signal: SigStage::Empty,
    };
    Ok(evt)
}

fn parse_payloads(
    reader: &mut BufReader<File>,
    inout: u64,
    mut size: usize,
) -> Result<Vec<TracePayload>> {
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
    let head = unsafe { mem::transmute::<[u8; PH_SIZE], PayloadHead>(buf) };
    let mut data = Vec::with_capacity(head.size as usize);
    unsafe {
        data.set_len(head.size as usize);
    }
    reader.read_exact(&mut data)?;

    Ok(TracePayload {
        inout: inout,
        index: head.index as usize,
        data,
    })
}
