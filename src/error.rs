/*
** DecoderError definitions and failure modes.
** This work is dedicated to the public domain under CC0 1.0 Universal.
*/
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecoderError {
    /* The buffer ended before the instruction was fully decoded. */
    TruncatedInstruction { offset: usize },
    
    /* The opcode is not recognized or is invalid in the current mode. */
    InvalidOpcode { offset: usize, opcode: u8 },
    
    /* Internal boundary check failure during parsing. */
    OutOfBoundsAccess { offset: usize },
    
    /* The encoding is valid in the ISA but not implemented in this version. */
    UnsupportedEncoding { offset: usize },
    
    /* Contradictory prefixes or invalid REX/VEX placement. */
    CorruptStream { offset: usize },
    
    /* Instruction exceeds the 15-byte x86 limit. */
    InstructionTooLong { offset: usize },
}

impl std::fmt::Display for DecoderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TruncatedInstruction { offset } => write!(f, "truncated instruction at offset {}", offset),
            Self::InvalidOpcode { offset, opcode } => write!(f, "invalid opcode {:#04x} at offset {}", opcode, offset),
            Self::OutOfBoundsAccess { offset } => write!(f, "out of bounds access at offset {}", offset),
            Self::UnsupportedEncoding { offset } => write!(f, "unsupported encoding at offset {}", offset),
            Self::CorruptStream { offset } => write!(f, "corrupt stream at offset {}", offset),
            Self::InstructionTooLong { offset } => write!(f, "instruction too long at offset {}", offset),
        }
    }
}

impl std::error::Error for DecoderError {}

pub type Result<T> = std::result::Result<T, DecoderError>;
