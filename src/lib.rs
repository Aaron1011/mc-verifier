#![recursion_limit="256"]

#![feature(async_closure)]
#![feature(type_alias_impl_trait)]

#![deny(clippy::option_unwrap_used, clippy::result_unwrap_used)]

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

use futures::stream::BoxStream;
use futures::prelude::*;


use tokio::sync::mpsc::channel;
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
use std::sync::Arc;

use std::future::Future;

use hyper_tls::HttpsConnector;

pub mod packet;
mod account_info;

use crate::packet::*;
use crate::packet::client::*;
use crate::packet::server::*;

use hyper::Client;

pub use account_info::created_date;
pub use packet::AuthedUser;

struct PacketCodec {
    state: u64,
    encryption: Option<Encryption>
}

impl PacketCodec {
    fn new() -> PacketCodec {
        PacketCodec { state: 0, encryption: None }
    }

    pub fn set_encryption(&mut self, enc: Encryption) {
        assert!(self.encryption.is_none());
        self.encryption = Some(enc);
    }

    fn encrypt(&mut self, packet: Box<dyn Packet>, dst: &mut BytesMut) {
        println!("Encrypting: {:?}", packet);
        let mut raw = BytesMut::with_capacity(dst.capacity());
        self.encode_raw(packet, &mut raw);


        let enc = self.encryption.as_mut().expect("Missing encrption!");

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
    _decrypt: Crypter,
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
                packets: Box::pin(future::ready(vec![Box::new(EncryptionRequest {
                    server_id: server_id.clone(),
                    pub_key: ByteArray::new(encoded_public_key),
                    verify_token: ByteArray::new(verify_token.to_vec())
                }) as Box<dyn Packet + Send>])),
                done: Ok(None)
            })
        });


        Some(Pin::from(Box::new(gen) as Box<dyn Future<Output = Result<HandlerAction, std::io::Error>> + Send>))
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

        let https = HttpsConnector::new().unwrap();
        let client = Client::builder()/*.executor(ExecutorCompat)*/.build::<_, hyper::Body>(https);
        //let client = Client::builder().build(https);
        let uri = format!("https://sessionserver.mojang.com/session/minecraft/hasJoined?username={}&serverId={}", self.username.as_ref().unwrap(), &hash)
            .parse().unwrap();

        println!("Sending request: {:?}", uri);

        Some(Pin::from(Box::new(async move {

            let res = client.get(uri).await.unwrap();
                

            let secret_key = secret_key.clone();
            println!("Got response: {:?}", res);

            let body = res.into_body();

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
            let enc = Encryption { encrypt, _decrypt: decrypt, block_size: Cipher::aes_128_cfb8().block_size() };


            let user: AuthedUser = serde_json::from_str(&data)?;
            for prop in &user.properties {
                println!("Verifying: {:?}", prop);
                assert!(prop.verify().expect("Error verifying property"))
            }

            let (message_tx, message_rx) = futures::channel::oneshot::channel();

            let user_data = UserData {
                user,
                disconnect: message_tx
            };


            let packet_fut = async move {
                let reason = message_rx.await.unwrap();
                vec![Box::new(LoginDisconnect { reason }) as Box<dyn Packet + Send>]
            };


            Ok(HandlerAction {
                encryption: Some(enc),
                packets: Box::pin(packet_fut),
                done: Ok(Some(user_data))
            })
        })))
    }
}

impl Encoder for PacketCodec {
    type Item = Box<dyn Packet + Send>;
    type Error = std::io::Error;

    fn encode(&mut self, packet: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        if self.encryption.is_some() {
            self.encrypt(packet, dst)
        } else {
            self.encode_raw(packet, dst)
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

pub struct ServerCanceller(futures::channel::oneshot::Sender<()>);

impl ServerCanceller {
    pub fn cancel(self) -> bool {
        self.0.send(()).is_ok()
    }

}


type ServerStream = impl Stream<Item = Result<UserData, Box<dyn Error + Send>>>;

pub struct McVerifier {
    pub stream: ServerStream, 
    cancel: futures::channel::oneshot::Sender<()>
}

impl McVerifier {
    pub async fn start(addr: SocketAddr) -> McVerifier {
        let (sender, receiver) = futures::channel::oneshot::channel();
        McVerifier {
            stream: server_stream(addr, receiver).await,
            cancel: sender
        }
    }

    pub fn into_inner(self) -> (ServerStream, ServerCanceller) {
        (self.stream, ServerCanceller(self.cancel))
    }
}

pub async fn server_stream(addr: SocketAddr, cancelled: futures::channel::oneshot::Receiver<()>) -> ServerStream {
    let listener = TcpListener::bind(&addr).await.expect("Unable to bind TCP listener!");

    let (stop_server, server_done) = channel::<()>(1);

    let stopped_future = future::select(server_done.into_future(), cancelled)
        .map(|_| Ok(()));

    let stop_server = Arc::new(stop_server);
    let stop_server_new = stop_server.clone();

    //println!("Listener: {:?}", listener);


    let tcp_server = listener.incoming()
        .then(move |socket| {
            let stop_server = stop_server_new.clone();


            let (user_tx, user_rx) = oneshot::channel();
            let mut user_tx = Some(user_tx);

            let proc_fut = async move {
                let socket = socket.unwrap();
                let socket_addr = socket.peer_addr().unwrap();

                println!("Got connection: {:?}", socket_addr);

                let codec = PacketCodec::new();

                let mut framed = Framed::new(socket, codec);


                let mut handler = SimpleHandler::new("".to_string());


                while let Some(pkt) = framed.next().await {
                    println!("Got packet: {:?}", pkt);
                    let mut ret = pkt.unwrap().handle_client(&mut handler);

                    let mut user_res = None;

                    if let Some(c) = ret.as_mut() {
                        let res = c.await.unwrap();

                        println!("Got res!");

                        if let Some(enc) = res.encryption {
                            framed.codec_mut().set_encryption(enc);
                        }


                        user_res = res.done.map_err(|e| Box::new(e) as Box<dyn std::error::Error>).unwrap();

                        let mut should_break = false;

                        println!("Got user res: {:?}", user_res);
                        if let Some(user) = user_res {
                            user_tx.take().unwrap().send(user).unwrap();
                            should_break = true;
                        }

                        for packet in res.packets.await {
                            framed.send(packet).await.unwrap();
                        }
                        if should_break {
                            break;
                        }
                    }
                }


                println!("Done: {:?}", socket_addr);
            };

            println!("Proc fut size: {}", std::mem::size_of_val(&proc_fut));

            tokio::spawn(proc_fut);
            user_rx.map(|r| Ok(r.unwrap()))
        });

    println!("TCP server size: {}", std::mem::size_of_val(&tcp_server));

    //tcp_server
    Box::pin(Compat::new(tcp_server).take_until(Box::new(Compat::new(Box::new(stopped_future)))).compat())
}
