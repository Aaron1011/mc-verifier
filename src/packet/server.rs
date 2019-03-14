use super::types::*;

use packet_macro::{packets, packet};

packets!{[

    #[packet(id = 1, side = "Server", state = "Login")]
    pub struct EncryptionRequest {
        pub server_id: String,
        pub pub_key: ByteArray,
        pub verify_token: ByteArray
    }
]}

pub trait ServerHandler {
    fn on_encryptionrequest(&mut self, request: &EncryptionRequest);
}
