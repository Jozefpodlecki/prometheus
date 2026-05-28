use crate::error::{DecoderError, Result};
use crate::isa::*;

/*
** Prefix constants for x86/x64.
** This work is dedicated to the public domain under CC0 1.0 Universal.
*/
const PREFIX_LOCK: u8 = 0xF0;
const PREFIX_REPNE: u8 = 0xF2;
const PREFIX_REPE: u8 = 0xF3;
const PREFIX_CS_OVERRIDE: u8 = 0x2E;
const PREFIX_SS_OVERRIDE: u8 = 0x36;
const PREFIX_DS_OVERRIDE: u8 = 0x3E;
const PREFIX_ES_OVERRIDE: u8 = 0x26;
const PREFIX_FS_OVERRIDE: u8 = 0x64;
const PREFIX_GS_OVERRIDE: u8 = 0x65;
const PREFIX_OPERAND_SIZE: u8 = 0x66;
const PREFIX_ADDRESS_SIZE: u8 = 0x67;

const MAX_INSTRUCTION_LENGTH: usize = 15;

struct DecodeSession<'a> {
    input: &'a [u8],
    cursor: usize,
}

#[derive(Debug, Default, Clone, Copy)]
struct Rex {
    w: bool,
    r: bool,
    x: bool,
    b: bool,
}

#[derive(Debug, Default, Clone, Copy)]
struct Rex2 {
    present: bool,
    w: bool,
    r: bool,
    x: bool,
    b: bool,
    r_prime: bool,
    x_prime: bool,
    b_prime: bool,
}

#[derive(Debug, Default, Clone, Copy)]
struct Vex {
    present: bool,
    r: bool,
    x: bool,
    b: bool,
    m: u8,
    w: bool,
    v: u8,
    l: bool,
    pp: u8,
}

#[derive(Debug, Default, Clone, Copy)]
struct Evex {
    present: bool,
    r: bool,
    x: bool,
    b: bool,
    r_prime: bool,
    m: u8,
    w: bool,
    v: u8,
    v_prime: bool,
    pp: u8,
    z: bool,
    l: u8,
    b_bit: bool,
    aaa: u8,
}

/*
** The XOP prefix structure (AMD eXtended Operations).
** XOP is a 3-byte prefix starting with 0x8F.
*/
#[derive(Debug, Default, Clone, Copy)]
struct Xop {
    present: bool,
    r: bool,
    x: bool,
    b: bool,
    m: u8,
    w: bool,
    v: u8,
    l: bool,
    pp: u8,
}

impl<'a> DecodeSession<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, cursor: 0 }
    }

    fn read_u8(&mut self) -> Result<u8> {
        if self.cursor < self.input.len() {
            let byte = self.input[self.cursor];
            self.cursor += 1;
            Ok(byte)
        } else {
            Err(DecoderError::TruncatedInstruction { offset: self.cursor })
        }
    }

    fn peek_u8(&self) -> Result<u8> {
        if self.cursor < self.input.len() {
            Ok(self.input[self.cursor])
        } else {
            Err(DecoderError::TruncatedInstruction { offset: self.cursor })
        }
    }

    fn read_i8(&mut self) -> Result<i8> {
        self.read_u8().map(|v| v as i8)
    }

    fn read_u32(&mut self) -> Result<u32> {
        if self.cursor + 4 <= self.input.len() {
            let mut b = [0u8; 4];
            b.copy_from_slice(&self.input[self.cursor..self.cursor+4]);
            self.cursor += 4;
            Ok(u32::from_le_bytes(b))
        } else {
            Err(DecoderError::TruncatedInstruction { offset: self.cursor })
        }
    }

    fn read_i32(&mut self) -> Result<i32> {
        self.read_u32().map(|v| v as i32)
    }

    fn read_u64(&mut self) -> Result<u64> {
        if self.cursor + 8 <= self.input.len() {
            let mut b = [0u8; 8];
            b.copy_from_slice(&self.input[self.cursor..self.cursor+8]);
            self.cursor += 8;
            Ok(u64::from_le_bytes(b))
        } else {
            Err(DecoderError::TruncatedInstruction { offset: self.cursor })
        }
    }
}

pub struct Decoder {
    arch: Architecture,
}

impl Decoder {
    pub fn new(arch: Architecture) -> Self {
        Self { arch }
    }

    pub fn decode(&self, input: &[u8], address: u64) -> Result<Instruction> {
        let mut session = DecodeSession::new(input);
        let mut prefixes = Vec::new();
        let mut segments = InstructionSegments::default();
        let mut rex = Rex::default();
        let mut rex2 = Rex2::default();
        let mut vex = Vex::default();
        let mut evex = Evex::default();
        let mut xop = Xop::default();
        let mut operand_size_override = false;
        let mut address_size_override = false;
        let mut segment_override: Option<Segment> = None;
        let mut has_rep = false;
        let mut has_repne = false;
        let mut has_lock = false;

        while session.cursor < input.len() {
            let byte = session.peek_u8()?;
            
            if byte == 0xC4 || byte == 0xC5 {
                let is_vex = if self.arch == Architecture::X64 { true } else { session.input.get(session.cursor + 1).map_or(false, |&n| (n & 0xC0) == 0xC0) };
                if is_vex {
                    if !prefixes.is_empty() || rex.w || rex2.present { return Err(DecoderError::CorruptStream { offset: session.cursor }); }
                    segments.prefixes.offset = 0;
                    if byte == 0xC5 {
                        let b1 = session.read_u8()?; let b2 = session.read_u8()?;
                        prefixes.push(b1); prefixes.push(b2);
                        vex = Vex { present: true, r: (b2 & 0x80) == 0, v: (!b2 >> 3) & 0x0F, l: (b2 & 0x04) != 0, pp: b2 & 0x03, m: 1, ..Vex::default() };
                    } else {
                        let b1 = session.read_u8()?; let b2 = session.read_u8()?; let b3 = session.read_u8()?;
                        prefixes.push(b1); prefixes.push(b2); prefixes.push(b3);
                        vex = Vex { present: true, r: (b2 & 0x80) == 0, x: (b2 & 0x40) == 0, b: (b2 & 0x20) == 0, m: b2 & 0x1F, w: (b3 & 0x80) != 0, v: (!b3 >> 3) & 0x0F, l: (b3 & 0x04) != 0, pp: b3 & 0x03 };
                    }
                    break;
                }
            }
            if byte == 0x62 {
                let is_evex = if self.arch == Architecture::X64 { true } else { session.input.get(session.cursor + 1).map_or(false, |&n| (n & 0xC0) == 0xC0) };
                if is_evex {
                    if !prefixes.is_empty() || rex.w || rex2.present { return Err(DecoderError::CorruptStream { offset: session.cursor }); }
                    segments.prefixes.offset = 0;
                    let p0 = session.read_u8()?; let p1 = session.read_u8()?; let p2 = session.read_u8()?; let p3 = session.read_u8()?;
                    prefixes.push(p0); prefixes.push(p1); prefixes.push(p2); prefixes.push(p3);
                    evex = Evex { present: true, r: (p1 & 0x80) == 0, x: (p1 & 0x40) == 0, b: (p1 & 0x20) == 0, r_prime: (p1 & 0x10) == 0, m: p1 & 0x03, w: (p2 & 0x80) != 0, v: (!p2 >> 3) & 0x0F, pp: p2 & 0x03, z: (p3 & 0x80) != 0, l: (p3 >> 5) & 0x03, b_bit: (p3 & 0x10) != 0, v_prime: (p3 & 0x08) == 0, aaa: p3 & 0x07 };
                    break;
                }
            }
            if byte == 0x8F {
                let is_xop = if self.arch == Architecture::X64 { true } else { session.input.get(session.cursor + 1).map_or(false, |&n| (n & 0xC0) == 0xC0) };
                if is_xop {
                    /* Read ahead to confirm XOP map (must be 0x08, 0x09, or 0x0A) */
                    if let Some(&next) = session.input.get(session.cursor + 1) {
                        let m = next & 0x1F;
                        if m >= 0x08 && m <= 0x0A {
                            if !prefixes.is_empty() || rex.w || rex2.present { return Err(DecoderError::CorruptStream { offset: session.cursor }); }
                            segments.prefixes.offset = 0;
                            let b1 = session.read_u8()?; let b2 = session.read_u8()?; let b3 = session.read_u8()?;
                            prefixes.push(b1); prefixes.push(b2); prefixes.push(b3);
                            xop = Xop { present: true, r: (b2 & 0x80) == 0, x: (b2 & 0x40) == 0, b: (b2 & 0x20) == 0, m, w: (b3 & 0x80) != 0, v: (!b3 >> 3) & 0x0F, l: (b3 & 0x04) != 0, pp: b3 & 0x03 };
                            break;
                        }
                    }
                }
            }
            if byte == 0xD5 && self.arch == Architecture::X64 {
                let _p0 = session.read_u8()?; let p1 = session.read_u8()?;
                prefixes.push(0xD5); prefixes.push(p1);
                rex2 = Rex2 { present: true, w: (p1 & 0x80) != 0, r: (p1 & 0x40) != 0, x: (p1 & 0x20) != 0, b: (p1 & 0x10) != 0, r_prime: (p1 & 0x04) != 0, x_prime: (p1 & 0x02) != 0, b_prime: (p1 & 0x01) != 0 };
                break;
            }
            if self.is_legacy_prefix(byte) {
                match byte {
                    PREFIX_OPERAND_SIZE => operand_size_override = true,
                    PREFIX_ADDRESS_SIZE => address_size_override = true,
                    PREFIX_LOCK => has_lock = true,
                    PREFIX_REPE => has_rep = true,
                    PREFIX_REPNE => has_repne = true,
                    PREFIX_CS_OVERRIDE => segment_override = Some(Segment::CS),
                    PREFIX_DS_OVERRIDE => segment_override = Some(Segment::DS),
                    PREFIX_ES_OVERRIDE => segment_override = Some(Segment::ES),
                    PREFIX_SS_OVERRIDE => segment_override = Some(Segment::SS),
                    PREFIX_FS_OVERRIDE => segment_override = Some(Segment::FS),
                    PREFIX_GS_OVERRIDE => segment_override = Some(Segment::GS),
                    _ => {}
                }
                // Handle TSX XACQUIRE/XRELEASE prefixes implicitly parsed as F2/F3
                prefixes.push(session.read_u8()?);
            } else if self.arch == Architecture::X64 && (0x40..=0x4F).contains(&byte) {
                let b = session.read_u8()?;
                rex = Rex { w: (b & 0x08) != 0, r: (b & 0x04) != 0, x: (b & 0x02) != 0, b: (b & 0x01) != 0 };
                prefixes.push(b);
            } else {
                break;
            }
            if session.cursor > MAX_INSTRUCTION_LENGTH { return Err(DecoderError::InstructionTooLong { offset: 0 }); }
        }
        segments.prefixes.length = session.cursor as u8;

        let (eff_op_size, eff_addr_size) = self.determine_sizes(operand_size_override, address_size_override, rex.w || rex2.w || evex.w || xop.w);
        segments.opcode.offset = session.cursor as u8;
        let mut is_two_byte = false;
        let mut is_three_byte = false;
        let opcode = if evex.present { let op = session.read_u8()?; is_two_byte = evex.m == 1 || evex.m == 2 || evex.m == 3; op }
        else if vex.present { let op = session.read_u8()?; is_two_byte = vex.m == 1 || vex.m == 2 || vex.m == 3; op }
        else if xop.present { let op = session.read_u8()?; is_two_byte = true; is_three_byte = xop.m == 0x09 || xop.m == 0x0A; op }
        else {
            let mut op = session.read_u8()?;
            if op == 0x0F {
                let next = session.peek_u8()?;
                if next == 0x38 || next == 0x3A || next == 0x1E { is_three_byte = true; let _map = session.read_u8()?; op = session.read_u8()?; }
                else { is_two_byte = true; op = session.read_u8()?; }
            }
            op
        };
        segments.opcode.length = (session.cursor as u8) - segments.opcode.offset;

        let (mnemonic, category, extension, cf, has_modrm) = self.resolve_opcode(opcode, is_two_byte, is_three_byte, &session)?;
        let mut operands = Vec::new();
        let vector_len: u16 = if evex.present { match evex.l { 0 => 128, 1 => 256, 2 => 512, _ => 128 } }
        else if vex.present { if vex.l { 256 } else { 128 } }
        else if xop.present { if xop.l { 256 } else { 128 } }
        else { 0 };

        if evex.present && (evex.v != 0 || evex.v_prime) {
            let v_reg_idx = evex.v | (if !evex.v_prime { 0x10 } else { 0 });
            let v_reg = self.decode_register(v_reg_idx, false, false, true, vector_len);
            
            let opmask = if evex.aaa != 0 {
                Some(self.decode_register(evex.aaa, false, false, false, 0xFFFF)) // K-registers
            } else {
                None
            };

            operands.push(Operand::Register { 
                reg: v_reg, 
                access: AccessType::Read, 
                visibility: Visibility::Explicit,
                opmask,
                zeroing: evex.z,
            });
        } else if (vex.present && vex.v != 0) || (xop.present && xop.v != 0) {
            let v_idx = if vex.present { vex.v } else { xop.v };
            let v_reg = self.decode_register(v_idx, false, false, true, vector_len);
            operands.push(Operand::Register { 
                reg: v_reg, 
                access: AccessType::Read, 
                visibility: Visibility::Explicit,
                opmask: None,
                zeroing: false,
            });
        }

        if has_modrm {
            let reg_is_dst = match opcode { 0x80..=0x83 => true, 0x8A | 0x8B | 0x03 | 0x2B | 0x3B | 0x33 | 0x8D | 0x28 | 0x58 | 0xDC | 0xDE | 0x90 => true, _ => false };
            let is_vec = vex.present || evex.present || xop.present || (is_three_byte && (opcode == 0xDC || opcode == 0xDE));
            let eff_vec_len = if is_vec && vector_len == 0 { 128 } else { vector_len };

            self.decode_modrm_sib(&mut session, &rex, &rex2, &vex, &evex, &xop, eff_op_size, eff_addr_size, eff_vec_len, reg_is_dst, segment_override, &mut segments, &mut operands, opcode)?;
        }

        let imm_start = session.cursor as u8;
        self.handle_immediate_operands(opcode, is_two_byte, &mut session, &rex, &rex2, &vex, &evex, &xop, eff_op_size, &mut operands)?;
        if session.cursor as u8 > imm_start {
            segments.immediate.offset = imm_start;
            segments.immediate.length = (session.cursor as u8) - imm_start;
        }

        let length = session.cursor as u8;
        let instruction_bytes = input[..session.cursor].to_vec();
        
        let has_xacquire = has_repne && has_lock && (mnemonic == Mnemonic::Add || mnemonic == Mnemonic::Sub || mnemonic == Mnemonic::Xor || mnemonic == Mnemonic::Mov);
        let has_xrelease = has_rep && has_lock && (mnemonic == Mnemonic::Add || mnemonic == Mnemonic::Sub || mnemonic == Mnemonic::Xor || mnemonic == Mnemonic::Mov);
        
        let mut instruction = Instruction {
            address, bytes: instruction_bytes, prefixes, mnemonic, operands,
            metadata: InstructionMetadata { length, architecture: self.arch, category, extension, control_flow: cf, flags: FlagEffect::default(),
                attributes: Attributes { has_lock, has_rep, has_repne, has_xacquire, has_xrelease, is_vector_op: vex.present || evex.present || xop.present, ..Attributes::default() }
            },
            segments,
        };
        self.apply_semantic_metadata(&mut instruction);
        crate::validator::Validator::validate(&instruction)?;
        Ok(instruction)
    }

    fn determine_sizes(&self, op_override: bool, addr_override: bool, rex_w: bool) -> (OperandSize, OperandSize) {
        let op_size = if self.arch == Architecture::X64 { if rex_w { OperandSize::Size64 } else if op_override { OperandSize::Size16 } else { OperandSize::Size32 } }
        else { if op_override { OperandSize::Size16 } else { OperandSize::Size32 } };
        let addr_size = if self.arch == Architecture::X64 { if addr_override { OperandSize::Size32 } else { OperandSize::Size64 } }
        else { if addr_override { OperandSize::Size16 } else { OperandSize::Size32 } };
        (op_size, addr_size)
    }

    fn is_legacy_prefix(&self, byte: u8) -> bool {
        match byte { PREFIX_LOCK | PREFIX_REPNE | PREFIX_REPE | PREFIX_CS_OVERRIDE | PREFIX_SS_OVERRIDE | PREFIX_DS_OVERRIDE | PREFIX_ES_OVERRIDE | PREFIX_FS_OVERRIDE | PREFIX_GS_OVERRIDE | PREFIX_OPERAND_SIZE | PREFIX_ADDRESS_SIZE => true, _ => false }
    }

    fn resolve_opcode(&self, opcode: u8, is_two_byte: bool, is_three_byte: bool, session: &DecodeSession) -> Result<(Mnemonic, InstructionCategory, IsaExtension, ControlFlow, bool)> {
        if is_three_byte {
            match opcode {
                /* Map 0x0F 0x38 */
                0xDC => Ok((Mnemonic::Aesenc, InstructionCategory::Arithmetic, IsaExtension::AES, ControlFlow::None, true)),
                0xDE => Ok((Mnemonic::Aesdec, InstructionCategory::Arithmetic, IsaExtension::AES, ControlFlow::None, true)),
                /* Map 0x0F 0x1E (CET) */
                0xFA => Ok((Mnemonic::Endbr64, InstructionCategory::ControlFlow, IsaExtension::CET, ControlFlow::None, false)), // Simplified endbr64 mapping logic
                /* XOP Map 0x09 */
                0x90 => Ok((Mnemonic::Vprotb, InstructionCategory::Arithmetic, IsaExtension::XOP, ControlFlow::None, true)),
                _ => {
                    // Check if it's the 0x1E map which is technically a 3-byte escape without standard 38/3A
                    if opcode == 0x1E {
                        let next = session.peek_u8().unwrap_or(0);
                        if next == 0xFA {
                            return Ok((Mnemonic::Endbr64, InstructionCategory::ControlFlow, IsaExtension::CET, ControlFlow::None, false));
                        }
                    }
                    Err(DecoderError::UnsupportedEncoding { offset: session.cursor })
                },
            }
        }
        else if is_two_byte {
            match opcode {
                0x05 => Ok((Mnemonic::Syscall, InstructionCategory::System, IsaExtension::Base, ControlFlow::Syscall, false)),
                0x84 => Ok((Mnemonic::Jz, InstructionCategory::ControlFlow, IsaExtension::Base, ControlFlow::ConditionalBranch, false)),
                0x85 => Ok((Mnemonic::Jnz, InstructionCategory::ControlFlow, IsaExtension::Base, ControlFlow::ConditionalBranch, false)),
                0x80..=0x8F => Ok((Mnemonic::Jmp, InstructionCategory::ControlFlow, IsaExtension::Base, ControlFlow::ConditionalBranch, false)),
                0x28 => Ok((Mnemonic::Vmovaps, InstructionCategory::Miscellaneous, IsaExtension::AVX, ControlFlow::None, true)),
                0x58 => Ok((Mnemonic::Vaddps, InstructionCategory::Arithmetic, IsaExtension::AVX, ControlFlow::None, true)),
                _ => {
                    let auto_m = crate::autogen_isa::auto_resolve_opcode_0f(opcode);
                    if auto_m != crate::autogen_isa::AutoMnemonic::Unknown {
                        Ok((Mnemonic::Auto(auto_m), InstructionCategory::Miscellaneous, IsaExtension::Base, ControlFlow::None, true))
                    } else {
                        Err(DecoderError::InvalidOpcode { offset: session.cursor, opcode })
                    }
                }
            }
        } else {
            match opcode {
                0x80..=0x83 => {
                    /* Handled post-resolution in Phase 3 */
                    Ok((Mnemonic::Unknown, InstructionCategory::Arithmetic, IsaExtension::Base, ControlFlow::None, true))
                },
                0xD8..=0xDF => {
                    /* x87 FPU Escape Map */
                    Ok((Mnemonic::Fadd, InstructionCategory::Arithmetic, IsaExtension::Base, ControlFlow::None, true)) // Simplified mapping
                },
                0x90 => Ok((Mnemonic::Nop, InstructionCategory::Miscellaneous, IsaExtension::Base, ControlFlow::None, false)),
                0xA4 | 0xA5 => Ok((Mnemonic::Movs, InstructionCategory::DataTransfer, IsaExtension::Base, ControlFlow::None, false)),
                0xC3 => Ok((Mnemonic::Ret, InstructionCategory::ControlFlow, IsaExtension::Base, ControlFlow::Return, false)),
                0xFF => Ok((Mnemonic::Call, InstructionCategory::ControlFlow, IsaExtension::Base, ControlFlow::Call, true)),
                0x88 | 0x89 | 0x8A | 0x8B => Ok((Mnemonic::Mov, InstructionCategory::DataTransfer, IsaExtension::Base, ControlFlow::None, true)),
                0x84 | 0x85 => Ok((Mnemonic::Test, InstructionCategory::Arithmetic, IsaExtension::Base, ControlFlow::None, true)),
                0x8D => Ok((Mnemonic::Lea, InstructionCategory::DataTransfer, IsaExtension::Base, ControlFlow::None, true)),
                0x01 | 0x03 => Ok((Mnemonic::Add, InstructionCategory::Arithmetic, IsaExtension::Base, ControlFlow::None, true)),
                0x29 | 0x2B => Ok((Mnemonic::Sub, InstructionCategory::Arithmetic, IsaExtension::Base, ControlFlow::None, true)),
                0x39 | 0x3B => Ok((Mnemonic::Cmp, InstructionCategory::Arithmetic, IsaExtension::Base, ControlFlow::None, true)),
                0x31 | 0x33 => Ok((Mnemonic::Xor, InstructionCategory::Arithmetic, IsaExtension::Base, ControlFlow::None, true)),
                0xB8..=0xBF => Ok((Mnemonic::Mov, InstructionCategory::DataTransfer, IsaExtension::Base, ControlFlow::None, false)),
                0x50..=0x57 => Ok((Mnemonic::Push, InstructionCategory::DataTransfer, IsaExtension::Base, ControlFlow::None, false)),
                0x58..=0x5F => Ok((Mnemonic::Pop, InstructionCategory::DataTransfer, IsaExtension::Base, ControlFlow::None, false)),
                0x9C => Ok((Mnemonic::Pushfq, InstructionCategory::DataTransfer, IsaExtension::Base, ControlFlow::None, false)),
                0x9D => Ok((Mnemonic::Popfq, InstructionCategory::DataTransfer, IsaExtension::Base, ControlFlow::None, false)),
                0xF8 => Ok((Mnemonic::Clc, InstructionCategory::Miscellaneous, IsaExtension::Base, ControlFlow::None, false)),
                0xF9 => Ok((Mnemonic::Stc, InstructionCategory::Miscellaneous, IsaExtension::Base, ControlFlow::None, false)),
                0xFC => Ok((Mnemonic::Cld, InstructionCategory::Miscellaneous, IsaExtension::Base, ControlFlow::None, false)),
                0xFD => Ok((Mnemonic::Std, InstructionCategory::Miscellaneous, IsaExtension::Base, ControlFlow::None, false)),
                0xCD => Ok((Mnemonic::Int, InstructionCategory::System, IsaExtension::Base, ControlFlow::Interrupt, false)),
                0xE8 => Ok((Mnemonic::Call, InstructionCategory::ControlFlow, IsaExtension::Base, ControlFlow::Call, false)),
                0xE9 => Ok((Mnemonic::Jmp, InstructionCategory::ControlFlow, IsaExtension::Base, ControlFlow::UnconditionalBranch, false)),
                _ => {
                    let auto_m = crate::autogen_isa::auto_resolve_opcode(opcode);
                    if auto_m != crate::autogen_isa::AutoMnemonic::Unknown {
                        Ok((Mnemonic::Auto(auto_m), InstructionCategory::Miscellaneous, IsaExtension::Base, ControlFlow::None, true))
                    } else {
                        Err(DecoderError::InvalidOpcode { offset: session.cursor, opcode })
                    }
                }
            }
        }
    }

    fn decode_modrm_sib(&self, session: &mut DecodeSession, rex: &Rex, rex2: &Rex2, vex: &Vex, evex: &Evex, _xop: &Xop, eff_op_size: OperandSize, eff_addr_size: OperandSize, vector_len: u16, reg_is_dst: bool, segment_override: Option<Segment>, segments: &mut InstructionSegments, operands: &mut Vec<Operand>, _opcode: u8) -> Result<()> {
        segments.modrm.offset = session.cursor as u8; segments.modrm.length = 1;
        let modrm = session.read_u8()?;
        let mode = (modrm >> 6) & 0x03;
        let reg_field = (modrm >> 3) & 0x07;
        let rm_field = modrm & 0x07;
        let reg = self.decode_register(reg_field, rex.r || vex.r || evex.r || rex2.r, rex2.r_prime || evex.r_prime, eff_op_size == OperandSize::Size64 || evex.w, vector_len);
        let reg_op = Operand::Register { reg, access: if reg_is_dst { AccessType::Write } else { AccessType::Read }, visibility: Visibility::Explicit, opmask: None, zeroing: false };
        let rm_op = if mode == 3 {
            let rm_reg = self.decode_register(rm_field, rex.b || vex.b || evex.b || rex2.b, rex2.b_prime, eff_op_size == OperandSize::Size64 || evex.w, vector_len);
            Operand::Register { reg: rm_reg, access: if reg_is_dst { AccessType::Read } else { AccessType::Write }, visibility: Visibility::Explicit, opmask: None, zeroing: false }
        } else {
            let mut base: Option<Register> = None;
            let mut index: Option<Register> = None;
            let mut scale = 0u8;
            let mut disp = 0i64;
            if rm_field == 4 {
                segments.sib.offset = session.cursor as u8; segments.sib.length = 1;
                let sib = session.read_u8()?;
                scale = 1 << ((sib >> 6) & 0x03);
                let index_field = (sib >> 3) & 0x07;
                let base_field = sib & 0x07;
                if index_field != 4 || (rex.x || rex2.x || vex.x || evex.x) { index = Some(self.decode_register(index_field, rex.x || rex2.x || vex.x || evex.x, rex2.x_prime, eff_addr_size == OperandSize::Size64, 0)); }
                if base_field == 5 && mode == 0 { disp = session.read_i32()? as i64; } else { base = Some(self.decode_register(base_field, rex.b || rex2.b || vex.b || evex.b, rex2.b_prime, eff_addr_size == OperandSize::Size64, 0)); }
            } else if rm_field == 5 && mode == 0 { if self.arch == Architecture::X64 { base = Some(Register::Rip); } disp = session.read_i32()? as i64; }
            else { base = Some(self.decode_register(rm_field, rex.b || rex2.b || vex.b || evex.b, rex2.b_prime, eff_addr_size == OperandSize::Size64, 0)); }
            let disp_start = session.cursor as u8;
            if mode == 1 { disp = session.read_i8()? as i64; } else if mode == 2 { disp = session.read_i32()? as i64; }
            if session.cursor as u8 > disp_start { segments.displacement.offset = disp_start; segments.displacement.length = (session.cursor as u8) - disp_start; }
            Operand::Memory { 
                mem: MemoryAccess { segment: segment_override, base, index, scale, displacement: disp, size: match eff_op_size { OperandSize::Size8 => 8, OperandSize::Size16 => 16, OperandSize::Size32 => 32, OperandSize::Size64 => 64, _ => 32 }, broadcast: evex.present && evex.b_bit, absolute_address: None }, 
                access: if reg_is_dst { AccessType::Read } else { AccessType::Write }, 
                visibility: Visibility::Explicit, opmask: None, zeroing: false 
            }
        };
        if reg_is_dst { operands.push(reg_op); operands.push(rm_op); } 
        else { operands.push(rm_op); operands.push(reg_op); }
        Ok(())
    }

    fn handle_immediate_operands(&self, opcode: u8, is_two_byte: bool, session: &mut DecodeSession, rex: &Rex, rex2: &Rex2, vex: &Vex, evex: &Evex, xop: &Xop, eff_op_size: OperandSize, operands: &mut Vec<Operand>) -> Result<()> {
        if is_two_byte { if (0x80..=0x8F).contains(&opcode) { operands.push(Operand::Immediate { imm: Immediate::I32(session.read_i32()?), visibility: Visibility::Explicit }); } }
        else {
            match opcode {
                0xB8..=0xBF => {
                    let reg_idx = opcode & 0x07;
                    let reg = self.decode_register(reg_idx, rex.b || rex2.b || vex.b || evex.b || xop.b, rex2.b_prime, eff_op_size == OperandSize::Size64 || rex2.w || evex.w || xop.w, 0);
                    operands.push(Operand::Register { reg, access: AccessType::Write, visibility: Visibility::Explicit, opmask: None, zeroing: false });
                    if eff_op_size == OperandSize::Size64 || rex2.w || evex.w || xop.w { operands.push(Operand::Immediate { imm: Immediate::U64(session.read_u64()?), visibility: Visibility::Explicit }); }
                    else if eff_op_size == OperandSize::Size16 { return Err(DecoderError::UnsupportedEncoding { offset: session.cursor }); }
                    else { operands.push(Operand::Immediate { imm: Immediate::U32(session.read_u32()?), visibility: Visibility::Explicit }); }
                },
                0x50..=0x57 => { let reg_idx = opcode & 0x07; let reg = self.decode_register(reg_idx, rex.b || rex2.b || vex.b || evex.b || xop.b, rex2.b_prime, self.arch == Architecture::X64, 0); operands.push(Operand::Register { reg, access: AccessType::Read, visibility: Visibility::Explicit, opmask: None, zeroing: false }); },
                0x58..=0x5F => { let reg_idx = opcode & 0x07; let reg = self.decode_register(reg_idx, rex.b || rex2.b || vex.b || evex.b || xop.b, rex2.b_prime, self.arch == Architecture::X64, 0); operands.push(Operand::Register { reg, access: AccessType::Write, visibility: Visibility::Explicit, opmask: None, zeroing: false }); },
                0xCD => { operands.push(Operand::Immediate { imm: Immediate::U8(session.read_u8()?), visibility: Visibility::Explicit }); },
                0xE8 | 0xE9 => { operands.push(Operand::Immediate { imm: Immediate::I32(session.read_i32()?), visibility: Visibility::Explicit }); },
                0xA4 | 0xA5 => {}, /* MOVS implicitly handled */
                _ => {}
            }
        }
        Ok(())
    }

    fn apply_semantic_metadata(&self, insn: &mut Instruction) { self.calculate_branch_targets(insn); self.add_implicit_operands(insn); self.populate_flag_effects(insn); self.populate_attributes(insn); }
    fn calculate_branch_targets(&self, insn: &mut Instruction) {
        if insn.metadata.control_flow == ControlFlow::ConditionalBranch || insn.metadata.control_flow == ControlFlow::UnconditionalBranch || insn.metadata.control_flow == ControlFlow::Call {
            for op in insn.operands.iter_mut() { if let Operand::Immediate { imm, .. } = op { if let Immediate::I32(rel) = *imm { let target = insn.address.wrapping_add(insn.metadata.length as u64).wrapping_add(rel as i64 as u64); *imm = Immediate::U64(target); } } }
        }

        /* Calculate RIP-relative addressing for memory operands */
        if self.arch == Architecture::X64 {
            for op in insn.operands.iter_mut() {
                if let Operand::Memory { mem, .. } = op {
                    if mem.base == Some(Register::Rip) {
                        let target = insn.address.wrapping_add(insn.metadata.length as u64).wrapping_add(mem.displacement as u64);
                        mem.absolute_address = Some(target);
                    }
                }
            }
        }
    }

    fn add_implicit_operands(&self, insn: &mut Instruction) {
        let stack_ptr = if self.arch == Architecture::X64 { Register::Rsp } else { Register::Esp };

        match insn.mnemonic {
            Mnemonic::Ret => {
                insn.operands.push(Operand::Register { reg: stack_ptr, access: AccessType::ReadWrite, visibility: Visibility::Implicit, opmask: None, zeroing: false });
            },
            Mnemonic::Call | Mnemonic::Push | Mnemonic::Pop | Mnemonic::Pushfq | Mnemonic::Popfq => {
                insn.operands.push(Operand::Register { reg: stack_ptr, access: AccessType::ReadWrite, visibility: Visibility::Implicit, opmask: None, zeroing: false });
            },
            Mnemonic::Syscall => {
                insn.operands.push(Operand::Register { reg: Register::Rcx, access: AccessType::Write, visibility: Visibility::Implicit, opmask: None, zeroing: false });
                insn.operands.push(Operand::Register { reg: Register::R11, access: AccessType::Write, visibility: Visibility::Implicit, opmask: None, zeroing: false });
            },
            Mnemonic::Mov => {},
            Mnemonic::Movs => {
                insn.operands.push(Operand::Register { reg: Register::Rsi, access: AccessType::ReadWrite, visibility: Visibility::Implicit, opmask: None, zeroing: false });
                insn.operands.push(Operand::Register { reg: Register::Rdi, access: AccessType::ReadWrite, visibility: Visibility::Implicit, opmask: None, zeroing: false });
                if insn.metadata.attributes.has_rep || insn.metadata.attributes.has_repne {
                    insn.operands.push(Operand::Register { reg: Register::Rcx, access: AccessType::ReadWrite, visibility: Visibility::Implicit, opmask: None, zeroing: false });
                }
            },
            Mnemonic::Cld | Mnemonic::Std | Mnemonic::Stc | Mnemonic::Clc => {},
            _ => {}
        }
    }

    fn populate_flag_effects(&self, insn: &mut Instruction) {
        use crate::isa::flags::*;
        let (tested, modified, set, cleared, undefined) = match insn.mnemonic {
            Mnemonic::Add | Mnemonic::Sub | Mnemonic::Cmp | Mnemonic::Test | Mnemonic::Neg | Mnemonic::Xadd => { (0, CF | PF | AF | ZF | SF | OF, 0, 0, 0) },
            Mnemonic::Adc | Mnemonic::Sbb => { (CF, CF | PF | AF | ZF | SF | OF, 0, 0, 0) },
            Mnemonic::Inc | Mnemonic::Dec => { (0, PF | AF | ZF | SF | OF, 0, 0, 0) }, // CF is explicitly NOT modified
            Mnemonic::Xor | Mnemonic::And | Mnemonic::Or => { (0, PF | ZF | SF, 0, CF | OF, 0) },
            Mnemonic::Not | Mnemonic::Mov | Mnemonic::Movs | Mnemonic::Lea | Mnemonic::Push | Mnemonic::Pop | Mnemonic::Xchg => { (0, 0, 0, 0, 0) },
            Mnemonic::Clc => (0, 0, 0, CF, 0), Mnemonic::Stc => (0, 0, CF, 0, 0), Mnemonic::Cld => (0, 0, 0, DF, 0), Mnemonic::Std => (0, 0, DF, 0, 0),
            Mnemonic::Pushfq => (0xFFFFFFFF, 0, 0, 0, 0), Mnemonic::Popfq => (0, 0xFFFFFFFF, 0, 0, 0),
            Mnemonic::Jz | Mnemonic::Jnz | Mnemonic::Js | Mnemonic::Jns | Mnemonic::Jo | Mnemonic::Jno | Mnemonic::Jb | Mnemonic::Jae => { let t = match insn.mnemonic { Mnemonic::Jz | Mnemonic::Jnz => ZF, Mnemonic::Js | Mnemonic::Jns => SF, Mnemonic::Jo | Mnemonic::Jno => OF, Mnemonic::Jb | Mnemonic::Jae => CF, _ => 0 }; (t, 0, 0, 0, 0) },
            Mnemonic::Btc | Mnemonic::Btr | Mnemonic::Bts => (0, CF, 0, 0, 0),
            _ => {
                // If not explicitly mapped, try resolving via autogen maps (if we had the data)
                let _auto_fx = crate::autogen_isa::auto_flag_effects(crate::autogen_isa::AutoMnemonic::Unknown);
                (0, 0, 0, 0, 0)
            },
        };
        insn.metadata.flags = FlagEffect { tested, modified, set, cleared, undefined };
    }

    fn populate_attributes(&self, insn: &mut Instruction) {
        let attr = &mut insn.metadata.attributes;
        match insn.mnemonic { 
            Mnemonic::Push | Mnemonic::Pop | Mnemonic::Ret | Mnemonic::Call | Mnemonic::Pushfq | Mnemonic::Popfq => { attr.is_stack_op = true; }, 
            Mnemonic::Syscall | Mnemonic::Int => { attr.is_privileged = true; }, 
            Mnemonic::Movs => { attr.is_string_op = true; },
            _ => {} 
        }
        if insn.metadata.category == InstructionCategory::System { attr.is_privileged = true; }
    }

    fn decode_register(&self, reg: u8, ext1: bool, ext2: bool, is_64bit: bool, vector_len: u16) -> Register {
        let mut index = reg + if ext1 { 8 } else { 0 } + if ext2 { 16 } else { 0 };
        if index > 31 { index = 0; }
        
        if vector_len == 0xFFFF {
            return match index {
                0 => Register::K0, 1 => Register::K1, 2 => Register::K2, 3 => Register::K3,
                4 => Register::K4, 5 => Register::K5, 6 => Register::K6, 7 => Register::K7,
                _ => Register::K0,
            };
        }

        if vector_len == 0xFFFE {
            return match index {
                0 => Register::St0, 1 => Register::St1, 2 => Register::St2, 3 => Register::St3,
                4 => Register::St4, 5 => Register::St5, 6 => Register::St6, 7 => Register::St7,
                _ => Register::St0,
            };
        }

        if vector_len > 0 {
            match vector_len {
                128 => match index { 0=>Register::Xmm0, 1=>Register::Xmm1, 2=>Register::Xmm2, 3=>Register::Xmm3, 4=>Register::Xmm4, 5=>Register::Xmm5, 6=>Register::Xmm6, 7=>Register::Xmm7, 8=>Register::Xmm8, 9=>Register::Xmm9, 10=>Register::Xmm10, 11=>Register::Xmm11, 12=>Register::Xmm12, 13=>Register::Xmm13, 14=>Register::Xmm14, 15=>Register::Xmm15, 16=>Register::Xmm16, 17=>Register::Xmm17, 18=>Register::Xmm18, 19=>Register::Xmm19, 20=>Register::Xmm20, 21=>Register::Xmm21, 22=>Register::Xmm22, 23=>Register::Xmm23, 24=>Register::Xmm24, 25=>Register::Xmm25, 26=>Register::Xmm26, 27=>Register::Xmm27, 28=>Register::Xmm28, 29=>Register::Xmm29, 30=>Register::Xmm30, 31=>Register::Xmm31, _=>Register::Xmm0 },
                256 => match index { 0=>Register::Ymm0, 1=>Register::Ymm1, 2=>Register::Ymm2, 3=>Register::Ymm3, 4=>Register::Ymm4, 5=>Register::Ymm5, 6=>Register::Ymm6, 7=>Register::Ymm7, 8=>Register::Ymm8, 9=>Register::Ymm9, 10=>Register::Ymm10, 11=>Register::Ymm11, 12=>Register::Ymm12, 13=>Register::Ymm13, 14=>Register::Ymm14, 15=>Register::Ymm15, 16=>Register::Ymm16, 17=>Register::Ymm17, 18=>Register::Ymm18, 19=>Register::Ymm19, 20=>Register::Ymm20, 21=>Register::Ymm21, 22=>Register::Ymm22, 23=>Register::Ymm23, 24=>Register::Ymm24, 25=>Register::Ymm25, 26=>Register::Ymm26, 27=>Register::Ymm27, 28=>Register::Ymm28, 29=>Register::Ymm29, 30=>Register::Ymm30, 31=>Register::Ymm31, _=>Register::Ymm0 },
                512 => match index { 0=>Register::Zmm0, 1=>Register::Zmm1, 2=>Register::Zmm2, 3=>Register::Zmm3, 4=>Register::Zmm4, 5=>Register::Zmm5, 6=>Register::Zmm6, 7=>Register::Zmm7, 8=>Register::Zmm8, 9=>Register::Zmm9, 10=>Register::Zmm10, 11=>Register::Zmm11, 12=>Register::Zmm12, 13=>Register::Zmm13, 14=>Register::Zmm14, 15=>Register::Zmm15, 16=>Register::Zmm16, 17=>Register::Zmm17, 18=>Register::Zmm18, 19=>Register::Zmm19, 20=>Register::Zmm20, 21=>Register::Zmm21, 22=>Register::Zmm22, 23=>Register::Zmm23, 24=>Register::Zmm24, 25=>Register::Zmm25, 26=>Register::Zmm26, 27=>Register::Zmm27, 28=>Register::Zmm28, 29=>Register::Zmm29, 30=>Register::Zmm30, 31=>Register::Zmm31, _=>Register::Zmm0 },
                _ => Register::Xmm0,
            }
        } else if is_64bit {
            match index { 0 => Register::Rax, 1 => Register::Rcx, 2 => Register::Rdx, 3 => Register::Rbx, 4 => Register::Rsp, 5 => Register::Rbp, 6 => Register::Rsi, 7 => Register::Rdi, 8 => Register::R8,  9 => Register::R9,  10 => Register::R10, 11 => Register::R11, 12 => Register::R12, 13 => Register::R13, 14 => Register::R14, 15 => Register::R15, 16 => Register::R16, 17 => Register::R17, 18 => Register::R18, 19 => Register::R19, 20 => Register::R20, 21 => Register::R21, 22 => Register::R22, 23 => Register::R23, 24 => Register::R24, 25 => Register::R25, 26 => Register::R26, 27 => Register::R27, 28 => Register::R28, 29 => Register::R29, 30 => Register::R30, 31 => Register::R31, _ => Register::Rax }
        } else {
            match index { 0 => Register::Eax, 1 => Register::Ecx, 2 => Register::Edx, 3 => Register::Ebx, 4 => Register::Esp, 5 => Register::Ebp, 6 => Register::Esi, 7 => Register::Edi, 8 => Register::R8d, 9 => Register::R9d, 10 => Register::R10d, 11 => Register::R11d, 12 => Register::R12d, 13 => Register::R13d, 14 => Register::R14d, 15 => Register::R15d, 16 => Register::R16d, 17 => Register::R17d, 18 => Register::R18d, 19 => Register::R19d, 20 => Register::R20d, 21 => Register::R21d, 22 => Register::R22d, 23 => Register::R23d, 24 => Register::R24d, 25 => Register::R25d, 26 => Register::R26d, 27 => Register::R27d, 28 => Register::R28d, 29 => Register::R29d, 30 => Register::R30d, 31 => Register::R31d, _ => Register::Eax }
        }
    }
}
