use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::io::Result;
use std::mem;
use std::collections::BTreeMap;
use event::{TraceHead, TracePayload, TraceEvent, TraceFlow, USER_ECALL};
use event::parse_sigaction;
use sysno::*;
use event::SigStage;

mod errno;
mod event;
mod mmap;
#[allow(unused)]
mod sysno;
mod signal;

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

    let mut events_map: BTreeMap<u64, TraceFlow> = BTreeMap::new();
    let mut vfork_req: Vec<TraceEvent> = vec![];
    while filesize >= TE_SIZE {
        let mut evt = parse_event(&mut reader)?;
        let advance = evt.head.totalsize as usize;
        assert_eq!(evt.head.magic, LK_MAGIC);
        assert_eq!(evt.head.headsize, TE_SIZE as u16);
        assert!(evt.head.totalsize >= evt.head.headsize as u32);

        /*
        println!("tid: {:#x} -> ({})[{:#x}, {:#x}, {}]",
            evt.head.sscratch, evt.head.inout, evt.head.cause, evt.head.epc, evt.head.ax[7]);
            */

        assert_eq!(evt.head.cause, USER_ECALL);

        let tid = evt.head.sscratch;
        let flow = match events_map.get_mut(&tid) {
            Some(q) => q,
            None => {
                // Start of each event is either req or clone.replay
                assert!(evt.head.inout == IN || evt.head.ax[7] == SYS_CLONE);
                println!("New events: {:#x}", tid);
                events_map.insert(tid, TraceFlow::new());
                let flow = events_map.get_mut(&tid).unwrap();
                if evt.head.inout == OUT {
                    let req = vfork_req.pop().unwrap();
                    flow.events.push(req);
                }
                flow
            },
        };

        match evt.head.inout {
            IN => {
                //println!("request: {}", evt.head.ax[7]);
                if let Some(last) = flow.events.last() {
                    assert_eq!(last.head.inout, OUT);
                }

                let sysno = evt.head.ax[7];
                match sysno {
                    SYS_CLONE => {
                        vfork_req.push(evt.clone());
                        flow.events.push(evt);
                    },
                    SYS_RT_SIGRETURN => {
                        //println!("signal exit: ");
                        flow.events.push(flow.signal_stack.pop().unwrap());
                    },
                    SYS_EXIT_GROUP => {
                        flow.events.push(evt);
                        print_events(tid, &flow.events);
                        events_map.remove(&tid);
                    },
                    _ => {
                        flow.events.push(evt);
                    },
                }
            },
            OUT => {
                let last = flow.events.last_mut().expect("No requests in event queue!");
                //assert_eq!(evt.head.ax[7], last.head.ax[7], "{:#x} != {:#x}", evt.head.ax[7], last.head.ax[7]);
                if evt.head.ax[7] != last.head.ax[7] {
                    println!("======================= unmatch: {} != {}", evt.head.ax[7], last.head.ax[7]);
                }

                if evt.head.ax[7] == SYS_RT_SIGACTION {
                    if let Some((sigaction, _)) = parse_sigaction(&evt) {
                        flow.sighand_set.insert(sigaction.handler);
                    }
                }

                // Todo: to distinguish signal by epc is NOT a proper method.
                // Try to find exact method.
                if flow.sighand_set.contains(&(evt.head.epc as usize)) {
                    assert!(evt.head.ax[7] != SYS_EXECVE);
                    let mut last = flow.events.pop().unwrap();
                    last.signal = SigStage::Exit(evt.head.ax[0]);
                    flow.signal_stack.push(last);

                    //println!("signal enter: {}", evt.head.ax[0]);
                    let mut sig_req = TraceEvent::default();
                    sig_req.signal = SigStage::Enter(evt.head.ax[0]);
                    sig_req.head.inout = OUT;
                    sig_req.head.ax[0] = evt.head.ax[0];
                    flow.events.push(sig_req);
                } else {
                    //println!("event out: {}", evt.head.ax[7]);
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

    for (id, flow) in events_map.iter() {
        print_events(*id, &flow.events);
    }
    Ok(())
}

fn print_events(tid: u64, events: &Vec<TraceEvent>) {
    println!("Task[{:#x}] ========>", tid);
    for evt in events {
        println!("{}", evt);
    }
    println!();
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
