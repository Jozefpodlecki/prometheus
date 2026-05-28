use crate::error::Result;
use crate::isa::{Instruction, Architecture};
use crate::decoder::Decoder;

/*
** Linear instruction sweep iterator.
** This work is dedicated to the public domain under CC0 1.0 Universal.
*/
pub struct InstructionIterator<'a> {
    decoder: Decoder,
    buffer: &'a [u8],
    address: u64,
    offset: usize,
}

impl<'a> InstructionIterator<'a> {
    /* Initializes a new linear sweep starting at the given virtual address. */
    pub fn new(arch: Architecture, buffer: &'a [u8], address: u64) -> Self {
        Self {
            decoder: Decoder::new(arch),
            buffer,
            address,
            offset: 0,
        }
    }
}

impl<'a> Iterator for InstructionIterator<'a> {
    type Item = Result<Instruction>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.buffer.len() {
            return None;
        }

        /*
        ** Attempt to decode the next instruction. On failure, we stop
        ** iteration. This behavior ensures that the engine remains
        ** deterministic and doesn't attempt to "guess" through a 
        ** corrupt or malicious stream.
        */
        match self.decoder.decode(&self.buffer[self.offset..], self.address) {
            Ok(instruction) => {
                let length = instruction.metadata.length as usize;
                self.offset += length;
                self.address += length as u64;
                Some(Ok(instruction))
            }
            Err(e) => {
                self.offset = self.buffer.len(); 
                Some(Err(e))
            }
        }
    }
}
