#![feature(slicing_syntax)]

extern crate openssl;
extern crate serialize;

use serialize::hex::ToHex;
use std::io;
use std::io::{Writer, MemWriter, MemReader, IoResult};


struct Thing {
    tag: u8,
    data: Vec<u8>
}

fn read_thing<R>(r: &mut R) -> IoResult<Thing> where R: Reader {
    let tag = try!(r.read_u8());
    println!("tag: {}", tag);
    let len_octets = try!(r.read_u8());
    let len =
        if len_octets & 0x80 == 0 {
            len_octets as u64
        } else {
            try!(r.read_be_uint_n((len_octets & 0x7F) as uint))
        };
    println!("len: {}", len);
    let data = try!(r.read_exact(len as uint));
    println!("data: {}", data[].to_hex());
    Ok(Thing {
        tag: tag,
        data: data
    })
}

fn write_thing<W>(w: &mut W, tag: u8, data: &[u8]) -> IoResult<()> where W: Writer {
    try!(w.write_u8(tag));
    let data_len = data.len();
    if data_len < 0x7F {
        try!(w.write_u8(data_len as u8));
    } else if data_len <= 0xFFFF {
        try!(w.write_u8(0x82));
        try!(w.write_be_u16(data_len as u16));
    } else if data_len <= 0xFFFF_FFFF {
        try!(w.write_u8(0x84));
        try!(w.write_be_u32(data_len as u32));
    } else {
        try!(w.write_u8(0x88));
        try!(w.write_be_u64(data_len as u64));
    }
    try!(w.write(data));
    Ok(())
}

/// components:
///   modulus
///   publicExponent
///   privateExponent
///   prime1
///   prime2
///   exponent1
///   exponent2
///   coefficient
pub fn write_der(components: [&[u8], ..8]) -> IoResult<Vec<u8>> {
    let mut seq_w = MemWriter::new();
    try!(write_thing(&mut seq_w, 2, [0u8][]));
    for data in components.iter() {
        try!(write_thing(&mut seq_w, 2, *data));
    }
    let mut w = MemWriter::new();
    try!(write_thing(&mut w, 48, seq_w.unwrap()[]));
    Ok(w.unwrap())
}


pub fn dump_der<R>(r: &mut R) -> IoResult<()> where R: Reader {
    loop {
        let thing = match read_thing(r) {
            Err(e) => {
                match e.kind {
                    io::EndOfFile => break,
                    _ => { return Err(e); }
                }
            }
            Ok(v) => v
        };
        if thing.tag == 48 {
            println!("sub_r");
            let mut sub_r = MemReader::new(thing.data);
            try!(dump_der(&mut sub_r));
            println!("end of sub_r");
        }
    }
    Ok(())
}

