/// REX prefix (64-bit mode only, bytes 0x40-0x4F)
#[derive(Debug, Default, Clone, Copy)]
pub struct Rex {
    /// REX.W - 64-bit operand size. When 1, instructs to use 64-bit operands.
    pub w: bool,
    
    /// REX.R - Extends ModRM.reg field. When 1, allows registers 8-15.
    pub r: bool,
    
    /// REX.X - Extends SIB.index field. When 1, allows index registers 8-15.
    pub x: bool,
    
    /// REX.B - Extends ModRM.rm or SIB.base field. When 1, allows base registers 8-15.
    pub b: bool,
}

/// REX2 prefix (APX - Advanced Performance Extensions, byte 0xD5 in 64-bit mode).
/// Introduced with Intel APX, extends GPR registers from 16 to 32 and adds
/// new opcode space. The prefix is 2 bytes: 0xD5 followed by a payload byte.
#[derive(Debug, Default, Clone, Copy)]
pub struct Rex2 {
    /// Indicates if the REX2 prefix is present in the instruction
    pub present: bool,
    
    /// REX2.W - 64-bit operand size override.
    /// When 1, forces 64-bit operand size regardless of other prefixes.
    pub w: bool,
    
    /// REX2.R - Extends ModRM.reg field.
    /// When 1, allows access to registers 16-31 (R16-R31).
    pub r: bool,
    
    /// REX2.X - Extends SIB.index field.
    /// When 1, allows index registers 16-31.
    pub x: bool,
    
    /// REX2.B - Extends ModRM.rm or SIB.base field.
    /// When 1, allows base registers 16-31.
    pub b: bool,
    
    /// High register extension for ModRM.reg (bit 4).
    /// Combines with REX2.R to encode registers 0-31.
    /// When 1, extends register index by an additional 16.
    pub r_prime: bool,
    
    /// High register extension for SIB.index (bit 4).
    /// Combines with REX2.X to encode index registers 0-31.
    pub x_prime: bool,
    
    /// High register extension for ModRM.rm or SIB.base (bit 4).
    /// Combines with REX2.B to encode base registers 0-31.
    pub b_prime: bool,
}

/// VEX prefix (Vector Extensions, bytes 0xC4 or 0xC5)
#[derive(Debug, Default, Clone, Copy)]
pub struct Vex {
    pub present: bool,
    
    /// REX.R extension (inverted). Inverts ModRM.reg when 0.
    pub r: bool,
    
    /// REX.X extension (inverted). Inverts SIB.index when 0. (3-byte VEX only)
    pub x: bool,
    
    /// REX.B extension (inverted). Inverts ModRM.rm when 0. (3-byte VEX only)
    pub b: bool,
    
    /// Opcode map selector (VEX.m-mmmmm).
    /// - 0b00001 = 0F (SSE/AVX base)
    /// - 0b00010 = 0F38 (SSE/AVX2)
    /// - 0b00011 = 0F3A (SSE/AVX2)
    pub m: u8,
    
    /// VEX.W bit - opcode-specific extension. Often selects between 128/256-bit ops.
    pub w: bool,
    
    /// Vector register operand (inverted form NOT vvvv). Source register for 3-op instructions.
    pub v: u8,
    
    /// Vector length flag. false=128-bit (XMM), true=256-bit (YMM)
    pub l: bool,
    
    /// Compressed legacy prefix (0=none, 1=0x66, 2=0xF3, 3=0xF2)
    pub pp: u8,
}

/// EVEX prefix (AVX-512, byte 0x62)
#[derive(Debug, Default, Clone, Copy)]
pub struct Evex {
    pub present: bool,
    
    /// REX.R extension (inverted)
    pub r: bool,
    
    /// REX.X extension (inverted)
    pub x: bool,
    
    /// REX.B extension (inverted)
    pub b: bool,
    
    /// High 16-bit register extension for reg field
    pub r_prime: bool,
    
    /// Opcode map selector (Evex.m)
    pub m: u8,
    
    /// EVEX.W bit - opcode extension (64-bit operand or vector length control)
    pub w: bool,
    
    /// Vector register operand (inverted)
    pub v: u8,
    
    /// High 16-bit register extension for vvvv field
    pub v_prime: bool,
    
    /// Compressed legacy prefix (0=none, 1=0x66, 2=0xF3, 3=0xF2)
    pub pp: u8,
    
    /// Zeroing mask flag. true=zero upper bits, false=merge with mask
    pub z: bool,
    
    /// Vector length (0=128, 1=256, 2=512, 3=reserved)
    pub l: u8,
    
    /// Broadcast/rounding control bit
    pub b_bit: bool,
    
    /// Opmask register selector (K0-K7)
    pub aaa: u8,
}

/*
** The XOP prefix structure (AMD eXtended Operations).
** XOP is a 3-byte prefix starting with 0x8F.
*/
#[derive(Debug, Default, Clone, Copy)]
pub struct Xop {
    /// Indicates if the XOP prefix is present in the instruction
    pub present: bool,
    
    /// REX.R extension bit (inverted). Inverts ModRM.reg when 0.
    /// Extends register field to 4 bits (GPR/XMM/YMM registers 8-15).
    pub r: bool,
    
    /// REX.X extension bit (inverted). Inverts SIB.index when 0.
    /// Extends index register to 4 bits.
    pub x: bool,
    
    /// REX.B extension bit (inverted). Inverts ModRM.rm or SIB.base when 0.
    /// Extends base/register field to 4 bits.
    pub b: bool,
    
    /// Opcode map selector (XOP map type).
    /// - 0x08 = XOP8 map (AMD XOP instructions)
    /// - 0x09 = XOP9 map (AMD XOP instructions)
    /// - 0x0A = XOPA map (AMD XOP instructions)
    pub m: u8,
    
    /// XOP.W bit - opcode-specific extension.
    /// Often selects between 64-bit and 32-bit operation or different opcode meanings.
    pub w: bool,
    
    /// Vector register operand (source). Inverted form (NOT vvvv).
    /// Specifies the first source register for 3-operand instructions.
    /// Value 0-15 maps to XMM/YMM registers.
    pub v: u8,
    
    /// Vector length flag.
    /// - false = 128-bit operation (XMM registers)
    /// - true = 256-bit operation (YMM registers)
    pub l: bool,
    
    /// Compressed legacy prefix (opcode extension).
    /// - 0b00 = No prefix
    /// - 0b01 = 0x66 operand size override
    /// - 0b10 = 0xF3 REP/REPE prefix
    /// - 0b11 = 0xF2 REPNE prefix
    pub pp: u8,
}