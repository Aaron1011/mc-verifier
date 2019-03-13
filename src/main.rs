#![recursion_limit="128"]

extern crate serde;

use ozelot::Server;

use tokio::prelude::*;
use tokio::io::copy;
use tokio::net::TcpListener;
use tokio::codec::{Decoder, Encoder, Framed};
use tokio::codec::BytesCodec;
use bytes::BytesMut;

use std::net::SocketAddr;

use packet::*;

pub mod packet;

struct ClientFuture {
    // The naming is a little weird - a 'Server'
    // struct represents the server's view of a single
    // client connection
    client: Server
}

struct PacketCodec;

impl Encoder for PacketCodec {
    type Item = Box<Packet>;
    type Error = std::io::Error;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl Decoder for PacketCodec {
    type Item = Box<Packet>;
    type Error = std::io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let mut len = VarInt::new(0);
        let mut slice = buf.as_ref();
        let reader = &mut slice as &mut std::io::Read;
        let res = len.read(reader);
        match res {
            Ok(()) => {}
            Err(ReadErr::TooSmall) => return Ok(None),
            Err(e) => return Err(e.into())
        }

        let diff = slice.as_ptr() as usize - buf.as_ref().as_ptr() as usize;

        println!("Slice: {:?} Orig: {:?} Difference: {:?}", slice.as_ptr(), buf.as_ref().as_ptr(), diff);


        let len: usize = len.into();

        if (buf.len() < len + diff) {
            println!("Not enough data read, returning Ok(None)");
            return Ok(None)
        }

        println!("Parsing packet!");
        let data = buf.split_to(len + diff);

        let pkt = packet::parse_packet(&packet::client::HANDLER_MAP, &data);

        println!("Got packet: {:?}", pkt);

        Ok(Some(pkt))
    }
}

/*impl Decoder for PacketCodec {

}*/

//impl Future for ClientFuture {
//}

fn main() {
    //let a: crate::packet::Packet = panic!();
    let addr = "127.0.0.1:25567".parse::<SocketAddr>().unwrap();
    let listener = TcpListener::bind(&addr).expect("Unable to bind TCP listener!");

    let tcp_server = listener.incoming()
        .map_err(|e| eprintln!("accept failed = {:?}", e))
        .for_each(|socket| {
            let framed = Framed::new(socket, PacketCodec);
            let (_writer, reader) = framed.split();

            let processor = reader
                .for_each(|bytes| {
                    println!("bytes: {:?}", bytes);
                    Ok(())
                })
                .map_err(|err| {
                    eprintln!("IO Error: {:?}", err);
                });

            tokio::spawn(processor)
        });


    println!("Running server on {:?}", addr);
    tokio::run(tcp_server);
}
