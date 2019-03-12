use super::types::*;

pub struct Handshake {
    pub version: VarInt,
    pub address: String,
    pub port: u16,
}


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
