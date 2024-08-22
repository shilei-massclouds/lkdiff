use lkdiff::event::parse_sigaction;
use lkdiff::event::SigStage;
use lkdiff::event::{parse_event, print_events, LK_MAGIC, TE_SIZE};
use lkdiff::event::{TraceEvent, TraceFlow, USER_ECALL};
use lkdiff::sysno::*;
use lkdiff::{IN, OUT};
use std::collections::{BTreeMap, HashSet};
use std::env;
use std::fs::File;
use std::io::BufReader;
use std::io::Result;

fn main() {
    let rfile;
    let mut level = 1;

    let args: Vec<String> = env::args().collect();
    if args.len() == 2 {
        rfile = &args[1];
    } else if args.len() == 3 {
        rfile = &args[2];
        if args[1] == "-2" {
            level = 2;
        }
    } else {
        println!("Usage: lkdiff [-2] trace.data");
        return;
    }
    parse_file(rfile, level).expect("reference is a bad file.");
}

fn parse_file(fname: &str, level: usize) -> Result<()> {
    let f = File::open(fname)?;
    let mut filesize = f.metadata().unwrap().len() as usize;
    let mut reader = BufReader::new(f);

    let mut sighand_set: HashSet<usize> = HashSet::new();
    let mut events_map: BTreeMap<u64, TraceFlow> = BTreeMap::new();
    let mut vfork_req: Vec<TraceEvent> = vec![];
    while filesize >= TE_SIZE {
        let mut evt = parse_event(&mut reader, level)?;
        let advance = evt.head.totalsize as usize;
        assert_eq!(evt.head.magic, LK_MAGIC);
        assert_eq!(evt.head.headsize, TE_SIZE as u16);
        assert!(evt.head.totalsize >= evt.head.headsize as u32);

        /*
        println!("tid: {:#x} -> ({})[{:#x}, {:#x}, {}]; pid: {:#x}",
            evt.head.sscratch, evt.head.inout, evt.head.cause,
            evt.head.epc, evt.head.ax[7], evt.head.satp);
            */

        assert_eq!(evt.head.cause, USER_ECALL);

        let tid = evt.head.sscratch;
        let flow = match events_map.get_mut(&tid) {
            Some(q) => q,
            None => {
                // Start of each event is either req or clone.replay
                assert!(evt.head.inout == IN || evt.head.ax[7] == SYS_CLONE);
                //println!("New events: {:#x}", tid);
                events_map.insert(tid, TraceFlow::new());
                let flow = events_map.get_mut(&tid).unwrap();
                if evt.head.inout == OUT {
                    let req = vfork_req.pop().unwrap();
                    flow.events.push(req);
                }
                flow
            }
        };

        match evt.head.inout {
            IN => {
                //println!("request: {}", evt.head.ax[7]);
                if let Some(last) = flow.events.last() {
                    if last.head.inout != OUT {
                        println!(
                            "======================= might be killed: {}",
                            last.head.ax[7]
                        );
                    }
                }

                let sysno = evt.head.ax[7];
                match sysno {
                    SYS_CLONE => {
                        vfork_req.push(evt.clone());
                        flow.events.push(evt);
                    }
                    SYS_RT_SIGRETURN => {
                        //println!("signal exit: ");
                        flow.events.push(flow.signal_stack.pop().unwrap());
                    }
                    SYS_EXIT_GROUP => {
                        flow.events.push(evt);
                        print_events(tid, &flow.events);
                        events_map.remove(&tid);
                    }
                    _ => {
                        flow.events.push(evt);
                    }
                }
            }
            OUT => {
                let last = flow.events.last_mut().expect("No requests in event queue!");
                //assert_eq!(evt.head.ax[7], last.head.ax[7], "{:#x} != {:#x}", evt.head.ax[7], last.head.ax[7]);
                if evt.head.ax[7] != last.head.ax[7] {
                    println!(
                        "======================= unmatch: {} != {}",
                        evt.head.ax[7], last.head.ax[7]
                    );
                }

                if evt.head.ax[7] == SYS_RT_SIGACTION {
                    if let Some((sigaction, _)) = parse_sigaction(&evt) {
                        println!("============ sigaction.handler {:#x}", sigaction.handler);
                        sighand_set.insert(sigaction.handler);
                    }
                }

                // Todo: to distinguish signal by epc is NOT a proper method.
                // Try to find exact method.
                if sighand_set.contains(&(evt.head.epc as usize)) {
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
                    last.result = evt.head.ax[0] as i64;
                    last.payloads.append(&mut evt.payloads);
                    last.head.inout = OUT;
                }
                //println!("replay: {}", last);
            }
            _ => unreachable!(),
        }

        filesize -= advance;
    }

    for (id, flow) in events_map.iter() {
        print_events(*id, &flow.events);
    }
    Ok(())
}
