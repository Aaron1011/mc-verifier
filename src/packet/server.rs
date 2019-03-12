use super::types::*;

struct EncryptionRequest {
    pub server_id: String,
    pub pub_key: ByteArray,
    pub verify_token: ByteArray
}
