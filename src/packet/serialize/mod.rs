use byteorder::{WriteBytesExt, BigEndian}
use serde::{ser, Serialize};

struct PacketSerializer {
    output: Vec<u8>,
    id: u64
}

impl<'a> ser::Serializer for &'a mut PacketSerializer {

    type Ok = ();

    type Error = ();

    type SerializeSeq = Self;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Self;
    type SerializeTupleVariant = Self;
    type SerializeMap = Self;
    type SerializeStruct = Self;
    type SerializeStructVariant = Self;

    fn serialize_bool(self, v: bool) -> Result<()> {
        self.output.write_u8(v as u8);
        Ok(())
    }

    fn serialize_i8(self, v: i8) -> Result<()> {
        self.output.write_i8(v);
        Ok(())
    }

    fn serialize_i16(self, v: i16) -> Result<()> {
        self.output.write_i16::<BigEndian>(v);
        Ok(())
    }

    fn serialize_i32(self, v: i32) -> Result<()> {
        self.output.write_i32::<BigEndian>(v);
        Ok(())
    }

    fn serialize_i64(self: v: i64) -> Result<()> {
        self.output.write_i64::<BigEndian>(v);
        Ok(())
    }

}
