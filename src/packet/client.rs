use super::types::*;
use packet_macro::packet;

#[packet(id = 0, side = "Client", state = "Login")]
pub struct Handshake {
    pub version: VarInt,
    pub address: String,
    pub port: u16,
}

/*impl Packet for Handshake {
    const SIDE: Side = crate::packet::Side::Client;
}*/



pub struct LoginStart {
    pub name: String
}

pub struct EncryptionResponse {
    pub shared_secret: ByteArray,
    pub verify_token: ByteArray
}

pub enum NextServerState {
    Status,
    Login
}
