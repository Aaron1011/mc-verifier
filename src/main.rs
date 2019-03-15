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
use tokio::sync::mpsc::Sender;
use tokio::net::TcpListener;
use tokio::codec::{Decoder, Encoder, Framed};
use bytes::BytesMut;


use std::net::SocketAddr;
use std::rc::Rc;
use std::cell::RefCell;
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
    encryption: Rc<RefCell<Option<Encryption>>>,
    real_encryption: Option<Encryption>
}

#[derive(Clone)]
struct EncryptionSettings {
    inner: Rc<RefCell<Option<Encryption>>>
}

impl EncryptionSettings {
    fn enable(&self, encryption: Encryption) {
        let mut ref_mut = self.inner.borrow_mut();
        if ref_mut.is_some() {
            panic!("Already enabled encrytion!");
        }
        *ref_mut = Some(encryption);
    }
}

impl PacketCodec {
    fn new() -> PacketCodec {
        PacketCodec { state: 0, encryption: Rc::new(RefCell::new(None)), real_encryption: None }
    }

    fn get_encryption_settings(&self) -> EncryptionSettings {
        EncryptionSettings {
            inner: self.encryption.clone()
        }
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
    //result: Vec<Box<Packet>>,
    ret_future: Box<Future<Item = (), Error = std::io::Error>>,
    public_key: Option<PKey<Private>>,
    encoded_public_key: Option<Vec<u8>>,
    verify_token: Option<[u8; 4]>,
    username: Option<String>,
    server_id: String,
    encryption: EncryptionSettings,
    packet_tx: Sender<Box<Packet>>
}

impl SimpleHandler {

    fn new(server_id: String, encryption: EncryptionSettings, packet_tx: Sender<Box<Packet>>) -> SimpleHandler {
        SimpleHandler {
            public_key: None,
            encoded_public_key: None,
            verify_token: None,
            ret_future: Box::new(tokio::prelude::future::ok(())),
            username: None,
            server_id,
            encryption,
            packet_tx
        }
    }

    fn send<T: Packet + 'static>(&mut self, packet: T) {
        let tx = self.packet_tx.clone();
        let ret_future = std::mem::replace(&mut self.ret_future, Box::new(future::ok(())));
        self.ret_future = Box::new(ret_future.and_then(|_| {
            tx.send(Box::new(packet))
                .map_err(|e| std::io::Error::new(ErrorKind::Other, e))
                .map(|_| ())
        }));
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

        self.send(EncryptionRequest {
            server_id: self.server_id.clone(),
            pub_key: ByteArray::new(self.encoded_public_key.clone().unwrap()),
            verify_token: ByteArray::new(verify_token.to_vec())
        });
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

        let hash = self.server_hash(&secret_key);

        // 4 is number of blocking DNS threads
        let https = HttpsConnector::new(4).unwrap();
        let client = Client::builder().build::<_, hyper::Body>(https);
        let uri = format!("https://sessionserver.mojang.com/session/minecraft/hasJoined?username={}&serverId={}", self.username.as_ref().unwrap(), &hash)
            .parse().unwrap();

        println!("Sending request: {:?}", uri);

        let enc = self.encryption.clone();

        let tx = self.packet_tx.clone();

        self.ret_future = Box::new(client.get(uri)
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
                    enc.enable(
                        Encryption { 
                            encrypt,
                            decrypt, 
                            block_size: Cipher::aes_128_cfb8().block_size() 
                        }
                    );
                })

            })
            .map_err(convert_hyper_err)
            .and_then(|_| {
                tx.send(Box::new(LoginDisconnect {
                    reason: "{\"text\": \"Successfully authenticated!\"}".to_string()
                }))
                .map(|_| ())
                .map_err(|e| std::io::Error::new(ErrorKind::Other, e))
            }))
    }
}

impl Encoder for PacketCodec {
    type Item = Box<Packet>;
    type Error = std::io::Error;

    fn encode(&mut self, packet: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        if self.real_encryption.is_some() {
            self.encrypt(packet, dst);
        } else {
            let enc = self.encryption.borrow_mut().take();
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
    env_logger::init();
    //let a: crate::packet::Packet = panic!();
    let addr = "127.0.0.1:25567".parse::<SocketAddr>().unwrap();
    let listener = TcpListener::bind(&addr).expect("Unable to bind TCP listener!");

    let tcp_server = listener.incoming()
        .map_err(|e| eprintln!("accept failed = {:?}", e))
        .for_each(move |socket| {

            tokio::spawn_lazy(|| {

                println!("Spawning!");

                let codec = PacketCodec::new();
                let crypto = codec.get_encryption_settings();
                let framed = Framed::new(socket, codec);
                let (writer, reader) = framed.split();
                let (tx, rx) = channel(10);

                
                let write_packets = rx.map_err(|e| std::io::Error::new(ErrorKind::Other, e)).forward(writer)
                        .map(|_| ())
                        .map_err(|e| eprintln!("Error when sending: {:?}", e));


                let mut handler = SimpleHandler::new("MyServer".to_string(), crypto.clone(), tx.clone());

                let processor = reader
                    .for_each(move |pkt| {

                        pkt.handle_client(&mut handler);
                        std::mem::replace(&mut handler.ret_future, Box::new(tokio::prelude::future::ok(())))

                        /*let packets: Vec<Box<Packet>> = handler.result.drain(..).collect();
                        let crypto_future_opt = handler.crypto_future.take();
                        let crypto = crypto.clone();


                        let new_tx = tx.clone();

                        crypto_future_opt
                            .unwrap_or_else(|| Box::new(tokio::prelude::future::ok(())))
                            .and_then(move |_| {
                                new_tx.clone().send_all(iter_ok(packets))
                                .map(|_| ())
                                .map_err(|e| std::io::Error::new(ErrorKind::Other, e))

                            })*/
                    })
                    .map_err(|err| {
                        eprintln!("IO Error: {:?}", err);
                    });

                let final_stream = processor.select(write_packets).map(|_v| ()).map_err(|err| eprintln!("Got error!"));

                return Box::new(final_stream)
            })
        });


    println!("Running server on {:?}", addr);
    tokio::run(tcp_server);
}
