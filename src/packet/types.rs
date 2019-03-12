use std::ops::Deref;

#[derive(Copy, Clone)]
pub struct VarInt {
    val: u64
}

impl VarInt {
    pub fn new(val: u64) -> VarInt {
        VarInt { val }
    }
}

impl Deref for VarInt {
    type Target = u64;
    fn deref(&self) -> &u64 {
        &self.val
    }
}

pub struct ByteArray {
}

pub enum PacketState {
    Login,
    Play
}
