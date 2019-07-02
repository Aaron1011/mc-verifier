pub mod client;
pub mod server;
mod types;


pub use types::{Packet, PacketState, Side, Readable, Writeable, VarInt, ReadResult, ReadErr, ParsedPacket, ByteArray};
pub use client::ClientHandler;
pub use server::ServerHandler;

use std::io::Read;
use std::collections::HashMap;

pub fn parse_packet(handlers: &HashMap<u64, Box<dyn Fn(&[u8]) -> ParsedPacket + Sync + Send>>, mut data: &[u8]) -> ParsedPacket {
    let data_ref = &mut data;
    let reader = data_ref as &mut dyn Read;

    let mut len = VarInt::new(0);
    len.read(reader).expect("Failed to read length!");

    let mut id = VarInt::new(0);
    id.read(reader).expect("Failed to read id!");

    println!("Constructing packet with id {:?} len {:?}", *id, *len);

    let handler = &handlers[&id.into()];
    handler(data)
}
