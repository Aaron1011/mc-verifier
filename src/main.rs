#![recursion_limit="128"]

extern crate serde;

use ozelot::Server;

use openssl::rsa::{Rsa, Padding};
use openssl::pkey::Private;
use openssl::pkey::PKey;
use openssl::rand::rand_bytes;
use openssl::sha::Sha1;

use tokio::prelude::*;
use tokio::prelude::stream::iter_ok;
use tokio::sync::mpsc::channel;
use tokio::io::copy;
use tokio::net::TcpListener;
use tokio::codec::{Decoder, Encoder, Framed};
use tokio::codec::BytesCodec;
use bytes::BytesMut;
use bytes::buf::BufMut;
use std::borrow::BorrowMut;


use std::net::SocketAddr;
use std::any::Any;
use std::sync::Arc;
use std::io::ErrorKind;

use packet::*;
use packet::client::*;
use packet::server::*;

use hyper::Client;
use hyper_tls::HttpsConnector;

use tokio::prelude::stream::SplitSink;

pub mod packet;

struct ClientFuture {
    // The naming is a little weird - a 'Server'
    // struct represents the server's view of a single
    // client connection
    client: Server
}

struct PacketCodec {
    state: u64
}

impl PacketCodec {
    fn new() -> PacketCodec {
        PacketCodec { state: 0 }
    }
}

struct SimpleHandler {
    result: Vec<Box<Packet>>,
    future: Option<Box<Future<Item = (), Error = std::io::Error> + Send>>,
    public_key: Option<PKey<Private>>,
    encoded_public_key: Option<Vec<u8>>,
    verify_token: Option<[u8; 4]>,
    username: Option<String>,
    server_id: String
}

impl SimpleHandler {

    fn new(server_id: String) -> SimpleHandler {
        SimpleHandler {
            result: Vec::new(),
            public_key: None,
            encoded_public_key: None,
            verify_token: None,
            future: None,
            username: None,
            server_id
        }
    }

    fn gen_keypair(&mut self) {
        // Based on https://gist.github.com/rust-play/6509bead4c6e13345f6535faf2db06bf
   
        let private_key = Rsa::generate(1024).expect("Failed to make private key"); // Minecraft always uses 1024-bit keys
        let public_key = PKey::from_rsa(private_key).expect("Failed to make public key");
        self.encoded_public_key = Some(public_key.public_key_to_der().expect("Failed to DER-encode"));
        self.public_key = Some(public_key);
    }

    fn server_hash(&self, secret: &[u8]) -> String {
        let mut sha = Sha1::new();
        sha.update(self.server_id.as_bytes());
        sha.update(secret);
        sha.update(self.encoded_public_key.as_ref().unwrap());
        let hash = sha.finish();

        // Weird Minecraft-specific encoding: see https://wiki.vg/Protocol_Encryption

        let mut encoded = String::new();
        if hash[0] & 0x80 != 0 {
            encoded.push('-'); // The hash is 'negative'
        }

        encoded += &hex::encode(hash);
        encoded
    }

}

fn convert_hyper_err(err: hyper::error::Error) -> std::io::Error {
    std::io::Error::new(ErrorKind::Other, err)
}

impl ClientHandler for SimpleHandler {

    fn on_handshake(&mut self, handshake: &Handshake) {
        println!("Handshake handler: {:?}", handshake);
    }

    fn on_loginstart(&mut self, login_start: &LoginStart) {
        println!("LoginStart handler: {:?}", login_start);

        self.username = Some(login_start.name.clone());

        self.gen_keypair();

        let mut verify_token = [0; 4];
        rand_bytes(&mut verify_token).expect("Failed to generate verify token");
        self.verify_token = Some(verify_token);

        self.result.push(Box::new(EncryptionRequest {
            server_id: self.server_id.clone(),
            pub_key: ByteArray::new(self.encoded_public_key.clone().unwrap()),
            verify_token: ByteArray::new(verify_token.to_vec())
        }));
    }

    fn on_encryptionresponse(&mut self, response: &EncryptionResponse) {
        println!("Decrypting encryption response...");

        let rsa = self.public_key.as_ref().unwrap().rsa().unwrap();
        let mut secret = vec![0; rsa.size() as usize];
        let secret_len = rsa.private_decrypt(
            &response.shared_secret.data,
            &mut secret,
            Padding::PKCS1
        ).expect("Failed to decrypt shared secret!");

        let mut verify_token = vec![0; rsa.size() as usize];
        let verify_len = rsa.private_decrypt(
            &response.verify_token.data,
            &mut verify_token,
            Padding::PKCS1
        ).expect("Failed to decrypt verify token!");

        if &verify_token[..verify_len] != self.verify_token.as_ref().unwrap() {
            panic!("Verify token incorrect: Should be {:?} but was {:?}", &verify_token[..verify_len],
                   self.verify_token.as_ref().unwrap());
        }

        println!("Verify token matches! Shared secret: {:?}", &secret[..secret_len]);

        let hash = self.server_hash(&secret[..secret_len]);

        // 4 is number of blocking DNS threads
        let https = HttpsConnector::new(4).unwrap();
        let client = Client::builder().build::<_, hyper::Body>(https);
        let uri = format!("https://sessionserver.mojang.com/session/minecraft/hasJoined?username={}&serverId={}", self.username.as_ref().unwrap(), &hash)
            .parse().unwrap();

        println!("Sending request: {:?}", uri);

        self.future = Some(Box::new(client.get(uri)
            .and_then(|res| {
                println!("Got response: {:?}", res);

                res.into_body().fold(vec![], |mut acc, chunk| {
                    acc.extend_from_slice(&chunk);
                    tokio::prelude::future::ok::<Vec<u8>, hyper::error::Error>(acc)
                }).map(|v| String::from_utf8(v).unwrap())
                .map(|data| {
                    println!("Got body: {:?}", data);
                })

            }).map_err(convert_hyper_err)));
    }
}

impl Encoder for PacketCodec {
    type Item = Box<Packet>;
    type Error = std::io::Error;

    fn encode(&mut self, packet: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let mut data = Vec::new();
        packet.get_id().write(&mut data);
        packet.write(&mut data);

        let len = VarInt::new(data.len() as u64);

        // Write the length of the id + data, followed
        // by the id + data
        let mut len_bytes: Vec<u8> = Vec::new();
        len.write(&mut len_bytes);

        dst.extend_from_slice(&len_bytes);
        dst.extend_from_slice(&data);

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

        println!("Parsing packet with state: {}", self.state);
        let data = buf.split_to(len + diff);

        let handlers = &(packet::client::HANDLERS)[self.state as usize];

        let pkt = packet::parse_packet(handlers, &data);


        println!("Got packet: {:?}", pkt);

        if let Ok(handshake) = pkt.any.downcast::<Handshake>() {
            println!("Setting next state: {:?}", handshake.next_state);
            self.state = handshake.next_state.into()
        }

        Ok(Some(pkt.boxed))
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
        .for_each(move |socket| {
            let framed = Framed::new(socket, PacketCodec::new());
            let (writer, reader) = framed.split();
            let (tx, rx) = channel(10);

            let sink = rx.map_err(|e| std::io::Error::new(ErrorKind::Other, e)).forward(writer)
                .map(|v| ())
                .map_err(|e| eprintln!("Error when sending: {:?}", e));


            
            tokio::spawn(sink);


            let new_tx = tx.clone();
            let mut handler = SimpleHandler::new("MyServer".to_string());

            let processor = reader
                .for_each(move |pkt| {

                    pkt.handle_client(&mut handler);

                    let packets: Vec<Box<Packet>> = handler.result.drain(..).collect();
                    let future_opt = handler.future.take();

                    new_tx.clone().send_all(iter_ok(packets))
                        .map(|v| ())
                        .map_err(|e| std::io::Error::new(ErrorKind::Other, e))
                        .and_then(|_| {
                            if let Some(future) = future_opt {
                                future
                            } else {
                                Box::new(tokio::prelude::future::ok(()))
                            }
                        })

                    /*writer.send_all(iter_ok::<_, std::io::Error>(packets)).map(|_v| ())
                        .map_err(|err| {
                            eprintln!("Error: {:?}", err);
                            err
                        })*/
                })
                .map_err(|err| {
                    eprintln!("IO Error: {:?}", err);
                });

            tokio::spawn(processor)
        });


    println!("Running server on {:?}", addr);
    tokio::run(tcp_server);
}
