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

pub enum Side {
    Client,
    Server
}

pub trait Packet {
    // This is actually serialized as a VarInt,
    // but we represent it as a u64 for convenience
    // If Minecraft ever has more than 2**64 packets,
    // we'll have (several) problems
    const ID: u64;
    const STATE: PacketState;
    const SIDE: Side;
}
