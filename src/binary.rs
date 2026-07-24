use std::io::{self, Read};

pub(crate) trait ReadLeExt: Read {
    fn read_u16_le(&mut self) -> io::Result<u16> {
        let mut bytes = [0_u8; 2];
        self.read_exact(&mut bytes)?;
        Ok(u16::from_le_bytes(bytes))
    }

    fn read_u32_le(&mut self) -> io::Result<u32> {
        let mut bytes = [0_u8; 4];
        self.read_exact(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn read_u64_le(&mut self) -> io::Result<u64> {
        let mut bytes = [0_u8; 8];
        self.read_exact(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn read_i64_le(&mut self) -> io::Result<i64> {
        let mut bytes = [0_u8; 8];
        self.read_exact(&mut bytes)?;
        Ok(i64::from_le_bytes(bytes))
    }
}

impl<T: Read + ?Sized> ReadLeExt for T {}
