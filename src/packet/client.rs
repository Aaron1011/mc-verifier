use super::types::*;
use packet_macro::{packets, packet};



packets!{[

    #[packet(id = 0, side = "Client", state = "Handshaking")]
    pub struct Handshake {
        pub version: VarInt,
        pub address: String,
        pub port: u16,
        pub next_state: VarInt
    }

    #[packet(id = 0, side = "Client", state = "Login")]
    pub struct LoginStart {
        pub name: String
    }

    #[packet(id = 1, side = "Client", state = "Login")]
    pub struct EncryptionResponse {
        pub shared_secret: ByteArray,
        pub verify_token: ByteArray
    }   

]}

/*impl Packet for Handshake {
    const SIDE: Side = crate::packet::Side::Client;
}*/


pub trait ClientHandler {
    fn on_handshake(&mut self, handshake: &Handshake);
    fn on_loginstart(&mut self, login_start: &LoginStart);
    fn on_encryptionresponse(&mut self, response: &EncryptionResponse);
}




pub enum NextServerState {
    Status,
    Login
}
