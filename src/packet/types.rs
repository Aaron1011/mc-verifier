use std::ops::Deref;
use byteorder::{ReadBytesExt, WriteBytesExt, BigEndian};

use std::io::{Read, Write, ErrorKind};
use std::fmt::Debug;
use std::any::Any;
use std::pin::Pin;
use std::future::Future;
use crate::Encryption;

use openssl::sign::Verifier;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;

const YGGDRASIL_KEY: &[u8] = include_bytes!("yggdrasil_session_pubkey.der");

use uuid::Uuid;
use serde::{Serialize, Deserialize, Serializer, Deserializer};
use base64_serde::base64_serde_type;

pub type HandlerRet = Option<Pin<Box<dyn Future<Output = Result<HandlerAction, failure::Error>> + Send>>>;

pub struct HandlerAction {
    pub encryption: Option<Encryption>,
    pub packets: Pin<Box<dyn Future<Output = Vec<Box<dyn Packet + Send>>> + Send>>,
    pub done: Result<Option<UserData>, Box<std::io::Error>>
}

use base64::STANDARD;
base64_serde_type!(pub Base64Standard, STANDARD);



#[derive(Debug, Deserialize)]
pub struct AuthedUser {
    pub id: Uuid,
    pub name: String,
    pub properties: Vec<Property>,
}

#[derive(Debug)]
pub struct UserData {
    pub user: AuthedUser,
    pub disconnect: futures::channel::oneshot::Sender<String>
}


mod base64_string {
    use serde::de::{Unexpected, Error as _};
    pub fn serialize<S>(string: &str, serializer: S) -> ::std::result::Result<S::Ok, S::Error> where S: super::Serializer {
        super::Base64Standard::serialize(string.as_bytes(), serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<String, D::Error> where D: super::Deserializer<'de> {
        Ok(String::from_utf8(super::Base64Standard::deserialize(deserializer)?).map_err(|e| {
            D::Error::invalid_value(Unexpected::Bytes(e.as_bytes()), &"valid UTF-8")
        })?)
    }
}


#[derive(Debug, Serialize, Deserialize)]
pub struct Property {
    pub name: String,
    #[serde(with = "base64_string")]
    pub value: String,
    #[serde(with = "Base64Standard")]
    pub signature: Vec<u8>
}

impl Property {
    pub fn verify(&self) -> Result<bool, Box<dyn std::error::Error>> {
        let encoded_value = base64::encode(&self.value);

        let key = PKey::public_key_from_der(YGGDRASIL_KEY)?;
        let mut verifier = Verifier::new(MessageDigest::sha1(), &key)?;
        verifier.update(encoded_value.as_bytes())?;
        Ok(verifier.verify(&self.signature)?)
    }
}

#[derive(Copy, Clone, Default, Debug)]
pub struct VarInt {
    val: u64
}

#[derive(Debug)]
pub struct ParsedPacket {
    pub boxed: Box<dyn Packet + Send>,
    pub any: Box<dyn Any>
}

impl VarInt {
    pub fn new(val: u64) -> VarInt {
        VarInt { val }
    }

    pub fn from_read(r: &mut dyn Read) -> Result<VarInt, ReadErr> {
        let mut var_int = VarInt::new(0);
        var_int.read(r)?;
        Ok(var_int)
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
    Other(Box<dyn std::error::Error + Send + Sync>)
}

impl std::error::Error for ReadErr {
    fn description(&self) -> &str {
        "Dummy description"
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
    fn write(&self, w: &mut dyn Write);
}

pub trait Readable {
    fn read(&mut self, r: &mut dyn Read) -> ReadResult;
}

impl Readable for u16 {
    fn read(&mut self, r: &mut dyn Read) -> ReadResult {
        *self = r.read_u16::<BigEndian>()?;
        Ok(())
    }
}

impl Writeable for u16 {
    fn write(&self, w: &mut dyn Write) {
        w.write_u16::<BigEndian>(*self).expect("Failed to write VarInt!");
    }
}

impl Writeable for [u8] {
    fn write(&self, w: &mut dyn Write) {
        w.write_all(&self).expect("Failed to write [u8]");
    }
}

impl Readable for String {
    fn read(&mut self, r: &mut dyn Read) -> ReadResult {
        let mut len = VarInt::new(0);
        len.read(r)?;
        let mut data = vec![0; len.into()];
        r.read_exact(&mut data)?;
        *self = String::from_utf8(data)?;
        Ok(())
    }
}

impl Writeable for String {
    fn write(&self, w: &mut dyn Write) {
        VarInt::new(self.len() as u64).write(w);
        self.as_bytes().write(w);
    }
}

impl Writeable for VarInt {
    fn write(&self, w: &mut dyn Write) {
        let mut val = self.val;

        loop {
            let mut temp: u8 = (val & 0b01111111) as u8;
            val >>= 7;
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
    fn read(&mut self, r: &mut dyn Read) -> ReadResult {
        let mut data = [0u8];

        let mut num_read = 0u64;
        let mut result = 0u64;
        //let mut read: u8;
        loop {
            r.read_exact(&mut data)?;
            let val: u8 = data[0] & 0b01111111;
            result |= u64::from(val) << (7 * num_read);

            num_read += 1;
            if num_read > 5 {
                panic!("VarInt is too big!");
            }

            if (data[0] & 0b10000000) == 0 {
                println!("Done reading VarInt");
                break
            }
            println!("Reading another byte");
        }

        self.val = result;
        Ok(())
    }
}

#[derive(Clone, Default, Debug)]
pub struct ByteArray {
    pub len: VarInt,
    pub data: Vec<u8>
}

impl ByteArray {
    pub fn new(data: Vec<u8>) -> ByteArray {
        ByteArray {
            len: VarInt::new(data.len() as u64),
            data
        }
    }
}

impl Readable for ByteArray {
    fn read(&mut self, r: &mut dyn Read) -> ReadResult {
        self.len.read(r)?;
        self.data = vec![0; self.len.into()];
        r.read_exact(&mut self.data)?;
        Ok(())
    }
}

impl Writeable for ByteArray {
    fn write(&self, w: &mut dyn Write) {
        self.len.write(w);
        self.data.as_slice().write(w); 
    }
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

pub trait Packet: Readable + Writeable + Debug + Send {

    fn get_id(&self) -> VarInt;

    fn handle_client(&self, handler: &mut dyn crate::packet::ClientHandler) -> HandlerRet;

    fn handle_server(&self, handler: &mut dyn crate::packet::ServerHandler) -> HandlerRet;


    // This is actually serialized as a VarInt,
    // but we represent it as a u64 for convenience
    // If Minecraft ever has more than 2**64 packets,
    // we'll have (several) problems
    /*const ID: u64;
    const STATE: PacketState;
    const SIDE: Side;*/
}
