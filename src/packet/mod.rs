pub mod client;
mod server;
mod types;


pub use types::{Packet, PacketState, Side, Readable, Writeable, VarInt, ReadResult, ReadErr};

use std::io::Read;
use std::collections::HashMap;

pub fn parse_packet(handlers: &HashMap<u64, Box<Fn(&[u8]) -> Box<Packet> + Sync>>, mut data: &[u8]) -> Box<Packet> {
    let data_ref = &mut data;
    let reader = data_ref as &mut Read;

    let mut len = VarInt::new(0);
    len.read(reader).expect("Failed to read length!");

    let mut id = VarInt::new(0);
    id.read(reader).expect("Failed to read id!");

    println!("Constructing packet with id {:?} len {:?}", *id, *len);

    let handler = &handlers[&id.into()];
    handler(data)
}
