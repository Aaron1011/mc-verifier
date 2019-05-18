#![recursion_limit="128"]

use openssl::rsa::{Rsa, Padding};
use openssl::pkey::Private;
use openssl::pkey::PKey;
use openssl::rand::rand_bytes;
use openssl::sha::Sha1;
use openssl::symm::{Cipher, Mode, Crypter};

use tokio::prelude::*;
use tokio::prelude::stream::iter_ok;
use tokio::sync::mpsc::channel;
use tokio::net::TcpListener;
use tokio::codec::{Decoder, Encoder, Framed};
use bytes::BytesMut;

use num_bigint::BigInt;


use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::io::ErrorKind;

use packet::*;
use packet::client::*;
use packet::server::*;

use hyper::Client;
use hyper_tls::HttpsConnector;

use std::alloc::System;

#[global_allocator]
static A: System = System;


pub mod packet;

struct PacketCodec {
    state: u64,
    encryption: Arc<Mutex<Option<Encryption>>>,
    real_encryption: Option<Encryption>
}

impl PacketCodec {
    fn new(enc: Arc<Mutex<Option<Encryption>>>) -> PacketCodec {
        PacketCodec { state: 0, encryption: enc, real_encryption: None }
    }

    fn encrypt(&mut self, packet: Box<Packet>, dst: &mut BytesMut) {
        println!("Encrypting!");
        let mut raw = BytesMut::with_capacity(dst.capacity());
        self.encode_raw(packet, &mut raw);


        let enc = self.real_encryption.as_mut().unwrap();

        let mut ciphertext = vec![0; raw.len() + enc.block_size];

        let count = enc.encrypt.update(&raw, &mut ciphertext).unwrap();
        enc.encrypt.finalize(&mut ciphertext[count..]).unwrap();
        ciphertext.truncate(count);

        dst.extend_from_slice(&ciphertext);
    }


    fn encode_raw(&mut self, packet: Box<Packet>, dst: &mut BytesMut) {
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
    }
}

struct Encryption {
    encrypt: Crypter,
    decrypt: Crypter,
    block_size: usize
}

struct SimpleHandler {
    result: Vec<Box<Packet>>,
    crypto_future: Option<Box<Future<Item = Encryption, Error = std::io::Error> + Send>>,
    public_key: Option<PKey<Private>>,
    encoded_public_key: Option<Vec<u8>>,
    verify_token: Option<[u8; 4]>,
    username: Option<String>,
    server_id: String,
}

impl SimpleHandler {

    fn new(server_id: String) -> SimpleHandler {
        SimpleHandler {
            result: Vec::new(),
            public_key: None,
            encoded_public_key: None,
            verify_token: None,
            crypto_future: None,
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
        let int = BigInt::from_signed_bytes_be(&hash);
        int.to_str_radix(16)
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
        let mut secret_len = rsa.private_decrypt(
            &response.shared_secret.data,
            &mut secret,
            Padding::PKCS1
        ).expect("Failed to decrypt shared secret!");

        println!("Changing secret len {:?}", secret_len);
        secret_len = 16;

        let secret_key = (&secret[..secret_len]).to_vec();

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
        println!("Secret key: {:?}", secret_key);

        let hash = self.server_hash(&secret_key);

        // 4 is number of blocking DNS threads
        let https = HttpsConnector::new(4).unwrap();
        let client = Client::builder().build::<_, hyper::Body>(https);
        let uri = format!("https://sessionserver.mojang.com/session/minecraft/hasJoined?username={}&serverId={}", self.username.as_ref().unwrap(), &hash)
            .parse().unwrap();

        println!("Sending request: {:?}", uri);


        self.crypto_future = Some(Box::new(client.get(uri)
            .and_then(move |res| {

                let secret_key = secret_key.clone();
                println!("Got response: {:?}", res);

                res.into_body().fold(vec![], |mut acc, chunk| {
                    acc.extend_from_slice(&chunk);
                    tokio::prelude::future::ok::<Vec<u8>, hyper::error::Error>(acc)
                }).map(|v| String::from_utf8(v).unwrap())
                .map(move |data| {
                    println!("Got body: {:?}", data);

                    let encrypt = Crypter::new(
                        Cipher::aes_128_cfb8(),
                        Mode::Encrypt,
                        &secret_key,
                        Some(&secret_key) // IV and secret are the same in Minecraft
                    ).unwrap();

                    let decrypt = Crypter::new(
                        Cipher::aes_128_cfb8(),
                        Mode::Decrypt,
                        &secret_key,
                        Some(&secret_key)
                    ).unwrap();
                    Encryption { encrypt, decrypt, block_size: Cipher::aes_128_cfb8().block_size() }
                })

            }).map_err(convert_hyper_err)));

        self.result.push(Box::new(LoginDisconnect {
            reason: "{\"text\": \"Successfully authenticated!\"}".to_string()
        }));
    }
}

impl Encoder for PacketCodec {
    type Item = Box<Packet>;
    type Error = std::io::Error;

    fn encode(&mut self, packet: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        if self.real_encryption.is_some() {
            self.encrypt(packet, dst);
        } else {
            let enc = self.encryption.lock().unwrap().take();
            if enc.is_some() {
                self.real_encryption = enc;
                self.encrypt(packet, dst)
            } else {
                self.encode_raw(packet, dst)
            }
        }
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

        if buf.len() < len + diff {
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
            let crypto: Arc<Mutex<Option<Encryption>>> = Arc::new(Mutex::new(None));
            let codec = PacketCodec::new(crypto.clone());
            let framed = Framed::new(socket, codec);
            let (writer, reader) = framed.split();
            let (tx, rx) = channel(10);

            let sink = rx.map_err(|e| std::io::Error::new(ErrorKind::Other, e)).forward(writer)
                .map(|_| ())
                .map_err(|e| eprintln!("Error when sending: {:?}", e));


            
            tokio::spawn(sink);


            let mut handler = SimpleHandler::new("".to_string());

            let processor = reader
                .for_each(move |pkt| {

                    pkt.handle_client(&mut handler);

                    let packets: Vec<Box<Packet>> = handler.result.drain(..).collect();
                    let crypto_future_opt = handler.crypto_future.take();
                    let crypto = crypto.clone();


                    let new_tx = tx.clone();

                    crypto_future_opt
                        .map(move |future| Box::new(future.map(move |c| *crypto.lock().unwrap() = Some(c))) as Box<Future<Item = (), Error = std::io::Error> + Send>)
                        .unwrap_or_else(|| Box::new(tokio::prelude::future::ok(())))
                        .and_then(move |_| {
                            println!("Sending: {:?}", packets);
                            new_tx.clone().send_all(iter_ok(packets))
                            .map(|_| ())
                            .map_err(|e| std::io::Error::new(ErrorKind::Other, e))

                        })

                        /*.and_then(move |_| {
                            if let Some(future) = crypto_future_opt {
                                                            } else {
                                Box::new(tokio::prelude::future::ok(()))
                            }
                        })*/

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
