use std::ops::Deref;
use std::fmt;
use serde::{Serialize, Deserialize, Serializer, Deserializer};
use byteorder::{ReadBytesExt, WriteBytesExt, BigEndian};
use serde::de::{self, Visitor, Error, SeqAccess};
use serde::ser::{SerializeSeq, SerializeTuple};

use std::io::{Read, Write, ErrorKind};
use std::fmt::Debug;

#[derive(Copy, Clone, Default, Debug)]
pub struct VarInt {
    val: u64
}

impl VarInt {
    pub fn new(val: u64) -> VarInt {
        VarInt { val }
    }
}

impl Into<u64> for VarInt {
    fn into(self) -> u64 {
        self.val
    }
}

impl Into<usize> for VarInt {
    fn into(self) -> usize {
        self.val as usize
    }
}

#[derive(Debug)]
pub enum ReadErr {
    // The provided buffer was too small
    TooSmall,
    // Some IO error
    IoError(std::io::Error),
    // Something else
    Other(Box<std::error::Error + Send + Sync>)
}

impl std::error::Error for ReadErr {
    fn description(&self) -> &str {
        return "Dummy description";
    }

    fn cause(&self) -> Option<&dyn std::error::Error> {
        None
    }
}

impl Into<std::io::Error> for ReadErr {
    fn into(self) -> std::io::Error {
        match self {
            ReadErr::TooSmall => std::io::Error::new(ErrorKind::UnexpectedEof, "Too Small"),
            ReadErr::IoError(e) => e,
            ReadErr::Other(e) => std::io::Error::new(ErrorKind::Other, e)
        }
    }
}

impl std::fmt::Display for ReadErr {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<std::string::FromUtf8Error> for ReadErr {
    fn from(e: std::string::FromUtf8Error) -> ReadErr {
        ReadErr::Other(Box::new(e))
    }
}

impl From<std::io::Error> for ReadErr {
    fn from(e: std::io::Error) -> ReadErr {
        match e.kind() {
            ErrorKind::UnexpectedEof => ReadErr::TooSmall,
            _ => ReadErr::IoError(e)
        }
    }
}

pub type ReadResult = Result<(), ReadErr>;

pub trait Writeable {
    fn write(&self, w: &mut Write);
}

pub trait Readable {
    fn read(&mut self, r: &mut Read) -> ReadResult;
}

impl Readable for u16 {
    fn read(&mut self, r: &mut Read) -> ReadResult {
        *self = r.read_u16::<BigEndian>()?;
        Ok(())
    }
}

impl Writeable for u16 {
    fn write(&self, w: &mut Write) {
        w.write_u16::<BigEndian>(*self).expect("Failed to write VarInt!");
    }
}

impl Writeable for [u8] {
    fn write(&self, w: &mut Write) {
        w.write_all(&self).expect("Failed to write [u8]");
    }
}

impl Readable for String {
    fn read(&mut self, r: &mut Read) -> ReadResult {
        let mut len = VarInt::new(0);
        len.read(r);
        let mut data = vec![0; len.into()];
        r.read_exact(&mut data)?;
        *self = String::from_utf8(data)?;
        Ok(())
    }
}

impl Writeable for String {
    fn write(&self, w: &mut Write) {
        VarInt::new(self.len() as u64).write(w);
        self.as_bytes().write(w);
    }
}

impl Writeable for VarInt {
    fn write(&self, w: &mut Write) {
        let mut val = self.val;

        loop {
            let mut temp: u8 = (val & 0b01111111) as u8;
            val = val >> 7;
            if val != 0 {
                temp |= 0b10000000;
            }
            w.write_all(&[temp]).expect("Failed to write VarInt");
            if val == 0 {
                break;
            }
        }
    }
}

impl Readable for VarInt {
    fn read(&mut self, r: &mut Read) -> ReadResult {
        let mut data = [0u8];

        let mut num_read = 0u64;
        let mut result = 0u64;
        //let mut read: u8;
        loop {
            r.read_exact(&mut data)?;
            let val: u8 = data[0] & 0b01111111;
            result |= (val << (7 * num_read)) as u64;

            num_read += 1;
            if (num_read > 5) {
                panic!("VarInt is too large!");
            }

            if (data[0] & 0b10000000) == 0 {
                break
            }
        }

        self.val = result;
        Ok(())
    }
}

pub struct ByteArray {
    pub len: VarInt,
    pub data: Vec<u8>
}


impl Deref for VarInt {
    type Target = u64;
    fn deref(&self) -> &u64 {
        &self.val
    }
}

/*
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

}*/


pub enum PacketState {
    Login,
    Play
}

pub enum Side {
    Client,
    Server
}

pub trait Packet: Readable + Writeable + Debug {
    // This is actually serialized as a VarInt,
    // but we represent it as a u64 for convenience
    // If Minecraft ever has more than 2**64 packets,
    // we'll have (several) problems
    /*const ID: u64;
    const STATE: PacketState;
    const SIDE: Side;*/
}
