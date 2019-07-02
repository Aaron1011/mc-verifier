use super::types::*;

use packet_macro::packets;

packets!{[

    #[packet(id = 0, side = "Server", state = "Login")]
    pub struct LoginDisconnect {
        pub reason: String
    }

    #[packet(id = 1, side = "Server", state = "Login")]
    pub struct EncryptionRequest {
        pub server_id: String,
        pub pub_key: ByteArray,
        pub verify_token: ByteArray
    }

    #[packet(id = 2, side = "Server", state = "Login")]
    pub struct LoginSuccess {
        pub uuid: String,
        pub username: String,
    }
]}

pub trait ServerHandler {
    fn on_encryptionrequest(&mut self, request: &EncryptionRequest) -> HandlerRet;
    fn on_loginsuccess(&mut self, pkt: &LoginSuccess) -> HandlerRet;
    fn on_logindisconnect(&mut self, pkt: &LoginDisconnect) -> HandlerRet;
}
