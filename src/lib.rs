#![recursion_limit="128"]

#![feature(async_await)]

use std::error::Error;

use futures::compat::{Future01CompatExt, Stream01CompatExt, Compat};

use json::object;

use stream_cancel::StreamExt as _;

use openssl::rsa::{Rsa, Padding};
use openssl::pkey::Private;
use openssl::pkey::PKey;
use openssl::rand::rand_bytes;
use openssl::sha::Sha1;
use openssl::symm::{Cipher, Mode, Crypter};

use futures::prelude::*;
use futures::stream;

use tokio::sync::mpsc::channel;
use tokio::sync::mpsc::Sender;
use tokio::net::TcpListener;
use tokio::codec::{Decoder, Encoder, Framed};
use bytes::BytesMut;

use futures::channel::oneshot;

use num_bigint::BigInt;

use futures::future;
use futures::StreamExt;
use futures::FutureExt;
use futures::TryFutureExt;




use std::pin::Pin;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::io::ErrorKind;

use std::future::Future;

use hyper_tls::HttpsConnector;

pub mod packet;

use crate::packet::*;
use crate::packet::client::*;
use crate::packet::server::*;

use hyper::Client;

pub struct ExecutorCompat;

impl futures01::future::Executor<Box<dyn futures01::Future<Item = (), Error = ()> + Send + 'static>> for ExecutorCompat {
    fn execute(&self, future: Box<dyn futures01::Future<Item = (), Error = ()> + Send>) -> Result<(), futures01::future::ExecuteError<Box<dyn futures01::Future<Item = (), Error = ()> + Send>>> {
        tokio::spawn(future.compat().map(|r| r.unwrap()));
        Ok(())
    }
}

struct PacketCodec {
    state: u64,
    encryption: Arc<Mutex<Option<Encryption>>>,
    real_encryption: Option<Encryption>
}

#[derive(Debug)]
enum Response {
    Packet(Box<dyn Packet + Send>),
    Shutdown(Sender<()>)
}

impl PacketCodec {
    fn new(enc: Arc<Mutex<Option<Encryption>>>) -> PacketCodec {
        PacketCodec { state: 0, encryption: enc, real_encryption: None }
    }

    fn encrypt(&mut self, packet: Box<dyn Packet>, dst: &mut BytesMut) {
        println!("Encrypting: {:?}", packet);
        let mut raw = BytesMut::with_capacity(dst.capacity());
        self.encode_raw(packet, &mut raw);


        let enc = self.real_encryption.as_mut().unwrap();

        let mut ciphertext = vec![0; raw.len() + enc.block_size];

        let count = enc.encrypt.update(&raw, &mut ciphertext).unwrap();
        enc.encrypt.finalize(&mut ciphertext[count..]).unwrap();
        ciphertext.truncate(count);

        dst.extend_from_slice(&ciphertext);
    }


    fn encode_raw(&mut self, packet: Box<dyn Packet>, dst: &mut BytesMut) {
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

pub struct Encryption {
    encrypt: Crypter,
    decrypt: Crypter,
    block_size: usize
}


struct SimpleHandler {
    public_key: Option<PKey<Private>>,
    encoded_public_key: Option<Vec<u8>>,
    verify_token: Option<[u8; 4]>,
    username: Option<String>,
    server_id: String,
}

impl SimpleHandler {

    fn new(server_id: String) -> SimpleHandler {
        SimpleHandler {
            public_key: None,
            encoded_public_key: None,
            verify_token: None,
            username: None,
            server_id,
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

    fn on_handshake(&mut self, handshake: &Handshake) -> HandlerRet {
        println!("Handshake handler: {:?}", handshake);
        None
    }

    fn on_loginstart(&mut self, login_start: &LoginStart) -> HandlerRet {
        println!("LoginStart handler: {:?}", login_start);

        self.username = Some(login_start.name.clone());

        self.gen_keypair();

        let mut verify_token = [0; 4];
        rand_bytes(&mut verify_token).expect("Failed to generate verify token");
        self.verify_token = Some(verify_token);

        let server_id = self.server_id.clone();
        let encoded_public_key = self.encoded_public_key.clone().unwrap();

        let gen = future::ok(()).and_then(async move |_| {
            Ok(HandlerAction {
                encryption: None,
                packets: vec![Box::new(EncryptionRequest {
                    server_id: server_id.clone(),
                    pub_key: ByteArray::new(encoded_public_key),
                    verify_token: ByteArray::new(verify_token.to_vec())
                })],
                done: Ok(None)
            })
        });


        Some(Pin::from(Box::new(gen) as Box<Future<Output = Result<HandlerAction, std::io::Error>> + Send>))
    }

    fn on_encryptionresponse(&mut self, response: &EncryptionResponse) -> HandlerRet {
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
        let client = Client::builder().executor(ExecutorCompat).build::<_, hyper::Body>(https);
        let uri = format!("https://sessionserver.mojang.com/session/minecraft/hasJoined?username={}&serverId={}", self.username.as_ref().unwrap(), &hash)
            .parse().unwrap();

        println!("Sending request: {:?}", uri);

        Some(Pin::from(Box::new(client.get(uri).compat()
            .map(|r| r.map_err(convert_hyper_err))
            .and_then(async move |res| {

                let secret_key = secret_key.clone();
                println!("Got response: {:?}", res);

                let body = res.into_body().compat();

                let data = String::from_utf8(body.fold(vec![], |mut acc, chunk| {
                    acc.extend_from_slice(&chunk.unwrap());
                    future::ready(acc)
                }).await).expect("Failed to parse Mojang response");

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
                let enc = Encryption { encrypt, decrypt, block_size: Cipher::aes_128_cfb8().block_size() };
                let packets = vec![Box::new(LoginDisconnect {
                    reason: object! {
                        "text" => format!("Successfully authenticated: {}", data)
                    }.to_string()
                }) as Box<dyn Packet + Send>];

                Ok(HandlerAction {
                    encryption: Some(enc),
                    packets,
                    done: Ok(Some(AuthedUser { body: data }))
                })
            }))))
    }
}

impl Encoder for PacketCodec {
    type Item = Box<dyn Packet + Send>;
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
    type Item = Box<dyn Packet + Send>;
    type Error = std::io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let mut len = VarInt::new(0);
        let mut slice = buf.as_ref();
        let reader = &mut slice as &mut dyn std::io::Read;
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

async fn handle_packet(
                       output: &mut (Sink<Box<dyn Packet + Send>, SinkError=std::io::Error> + Send + Unpin),
                       handler_ret: HandlerRet,
                       crypto: Arc<Mutex<Option<Encryption>>>, addr: SocketAddr,
                       mut tx: Sender<Response>,
                       on_disconnect: Arc<Box<dyn Fn(SocketAddr) -> bool + Send + Sync + 'static>>,
                       stop_server: Arc<Sender<()>>,
                       ) -> Result<Option<AuthedUser>, Box<dyn Error>> {


    let mut packets = vec![];
    let mut done = Ok(None);

    println!("Got  ret: {:?}", handler_ret.is_some());
    if let Some(c) = handler_ret {
        let mut res = c.await?;
        if let Some(enc) = res.encryption {
            *crypto.lock().unwrap() = Some(enc);
        }
        packets = res.packets;
        done = res.done;
    }


    let addr = addr.clone();

    
    println!("Sending: {:?}", packets);

    for packet in packets {
        output.send(packet).await.unwrap();
    }

    //let mut packet_stream = stream::iter(packets.into_iter());

    //tx.send_all(&mut packet_stream).await?;

    if (done.is_err() || done.as_ref().unwrap().is_some()) &&on_disconnect(addr) {
        println!("Stopping for real!");
        let mut inner = (*stop_server).clone();
        inner.send(()).await.unwrap();
    }

    done.map_err(|e| Box::new(e) as Box<std::error::Error>)
}



pub fn server_stream(addr: SocketAddr, on_disconnect: Box<dyn Fn(SocketAddr) -> bool + Send + Sync + 'static>) -> impl Stream<Item = Result<AuthedUser, Box<Error>>> {
    //let a: crate::packet::Packet = panic!();
    let listener = TcpListener::bind(&addr).expect("Unable to bind TCP listener!");
    let on_disconnect = Arc::new(on_disconnect);

    let (stop_server, mut server_done) = channel::<()>(1);
    let stop_server = Arc::new(stop_server);
    let stop_server_new = stop_server.clone();

    let on_disconnect = on_disconnect.clone();

    let tcp_server = listener.incoming()
        .then(move |socket| {
            let on_disconnect = on_disconnect.clone();
            let stop_server = stop_server_new.clone();


            let (mut user_tx, mut user_rx) = oneshot::channel();

            let proc_fut = async move {
                let socket = socket.unwrap();
                let socket_addr = socket.peer_addr().unwrap();

                println!("Got connection: {:?}", socket_addr);

                let crypto: Arc<Mutex<Option<Encryption>>> = Arc::new(Mutex::new(None));
                let codec = PacketCodec::new(crypto.clone());

                let framed = Framed::new(socket, codec);


                let (mut writer, mut reader) = framed.split();
                let (tx, mut rx) = channel(10);

                /*tokio::spawn(async move {
                    while let Some(r) = rx.next().await {
                        match r {
                            Response::Packet(p) => writer.send(p).await.unwrap(),
                            Response::Shutdown(mut s) => {
                                s.send(()).await.map_err(|e| eprintln!("Other failed to shutdown: {:?}", e));
                            }
                        }
                    }
                });*/

                //let sink = rx.forward(writer);
                /*let sink = rx.for_each(async move |r| {
                });


                tokio::spawn(sink);*/


                let mut handler = SimpleHandler::new("".to_string());
                let stop_server_new = stop_server.clone();

                let on_disconnect_new = on_disconnect.clone();


                while let Some(pkt) = reader.next().await {
                    println!("Got packet: {:?}", pkt);
                    let ret = pkt.unwrap().handle_client(&mut handler);
                    let res = handle_packet(
                        &mut writer, ret, crypto.clone(), addr, tx.clone(), on_disconnect.clone(), stop_server_new.clone()
                    ).map(|r| r.unwrap()).await;

                    println!("Got user res: {:?}", res);
                    if let Some(user) = res {
                        user_tx.send(user).unwrap();
                        break;
                    }
                }

                
                println!("Done: {:?}", socket_addr);
                if on_disconnect_new(socket_addr) {
                    let mut do_stop = (*stop_server).clone();
                    // We don't care if we get an error - that
                    // just means that we already tried to stop the server
                    if let Err(e) = do_stop.send(()).await {
                        eprintln!("Failed to shutdown: {:?}", e);
                    }
                }
            };

            tokio::spawn(proc_fut);
            user_rx.map(|r| Ok(r.unwrap()))
        });

    Compat::new(tcp_server).take_until(Box::new(Compat::new(Box::new(server_done.into_future().map(|_| Ok(())))))).compat()
    //futures::stream::select(tcp_server, server_done.map(|_| Err(Box::new(std::io::Error::new()
}
