use std::io::prelude::*;
use std::io::Result;
use std::fs::File;
use std::io::BufReader;
use std::mem;
use crate::event::TracePayload;

#[repr(C)]
struct PayloadHead {
    magic: u16,
    index: u16,
    size: u32,
}

const PH_SIZE: usize = mem::size_of::<PayloadHead>();

pub fn parse_payloads(
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
