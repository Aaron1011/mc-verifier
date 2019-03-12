use std::ops::Deref;
use std::fmt;
use serde::{Serialize, Deserialize, Serializer, Deserializer};
use serde::de::{self, Visitor, Error, SeqAccess};
use serde::ser::{SerializeSeq, SerializeTuple};

use std::io::{Read, Write};


#[derive(Copy, Clone)]
pub struct VarInt {
    val: u64
}

impl VarInt {
    pub fn new(val: u64) -> VarInt {
        VarInt { val }
    }
}

trait Writeable {
    fn write<W: Write>(&self, w: W);
}

trait Readable {
    fn read<R: Read>(&mut self, r: R);
}

impl Serialize for VarInt {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut val = self.val;
        let mut res;

        let mut data: Vec<u8> = Vec::new();
        loop {
            let mut temp: u8 = (val & 0b01111111) as u8;
            val = val >> 7;
            if val != 0 {
                temp |= 0b10000000;
            }
            data.push(temp);
            if val == 0 {
                break;
            }
        }

        let mut tup = serializer.serialize_tuple(data.len())?;
        for entry in data {
            res = tup.serialize_element(&entry)?;
        }
        tup.end()
    }
}



impl<'de> Deserialize<'de> for VarInt {


    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<VarInt, D::Error> {

        struct ByteVisitor;

        impl<'de> Visitor<'de> for ByteVisitor {
            type Value = VarInt;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a VarInt byte")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut num_read = 0u64;
                let mut result = 0u64;
                let mut read: u8;
                loop {
                    read = seq.next_element()?.expect("Missing next val!");
                    let val: u8 = read & 0b01111111;
                    result |= (val << (7 * num_read)) as u64;

                    num_read += 1;
                    if (num_read > 5) {
                        return Err(A::Error::custom("VarInt is too large!".to_string()))
                    }

                    if (read & 0b10000000) == 0 {
                        break
                    }
                }

                Ok(VarInt { val: result })
            }
        }

        deserializer.deserialize_seq(ByteVisitor)

    }
}

impl Deref for VarInt {
    type Target = u64;
    fn deref(&self) -> &u64 {
        &self.val
    }
}

pub struct ByteArray {
    pub len: VarInt,
    pub data: Vec<u8>
}

impl Serialize for ByteArray {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut tup = serializer.serialize_tuple(2)?;
        tup.serialize_element(&self.len);
        tup.serialize_element(self.data.as_slice());
        tup.end()
    }
}

impl Deserialize for ByteArray {
    struct ByteArrayVisitor;

    impl<'de> Visitor<'de> for ByteArrayVisitor {
        type Value = ByteArray;
    }

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a VarInt-prefixed byte array")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let len: VarInt = seq.next_element()?;
        let data: Vec<u8> = seq.next_element() 
    }

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
