
use super::{DecoderError, Result};

pub struct DecodeSession<'a> {
    pub input: &'a [u8],
    pub cursor: usize,
}

impl<'a> DecodeSession<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        Self { input, cursor: 0 }
    }

    #[inline]
    pub fn read_u8(&mut self) -> Result<u8> {
        if self.cursor < self.input.len() {
            let byte = self.input[self.cursor];
            self.cursor += 1;
            Ok(byte)
        } else {
            Err(DecoderError::TruncatedInstruction { offset: self.cursor })
        }
    }

    #[inline]
    pub fn peek_u8(&self) -> Result<u8> {
        if self.cursor < self.input.len() {
            Ok(self.input[self.cursor])
        } else {
            Err(DecoderError::TruncatedInstruction { offset: self.cursor })
        }
    }

    #[inline]
    pub fn read_i8(&mut self) -> Result<i8> {
        self.read_u8().map(|v| v as i8)
    }

    #[inline]
    pub fn read_u16(&mut self) -> Result<u16> {
        self.read_bytes::<2>().map(u16::from_le_bytes)
    }

    #[inline]
    pub fn read_u32(&mut self) -> Result<u32> {
        self.read_bytes::<4>().map(u32::from_le_bytes)
    }

    #[inline]
    pub fn read_i32(&mut self) -> Result<i32> {
        self.read_u32().map(|v| v as i32)
    }

    #[inline]
    pub fn read_u64(&mut self) -> Result<u64> {
        self.read_bytes::<8>().map(u64::from_le_bytes)
    }

    #[inline]
    fn read_bytes<const N: usize>(&mut self) -> Result<[u8; N]> {
        if self.cursor + N <= self.input.len() {
            let bytes = self.input[self.cursor..self.cursor + N]
                .try_into()
                .expect("slice length mismatch");
            self.cursor += N;
            Ok(bytes)
        } else {
            Err(DecoderError::TruncatedInstruction { offset: self.cursor })
        }
    }
}