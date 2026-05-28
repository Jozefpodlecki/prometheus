pub mod session;
pub mod opcode_resolver;
pub mod register;
mod modrm;
mod immediate;
mod flags;
mod attributes;
mod branch;
mod implicit;
mod types;

pub use types::*;

use crate::decoder::session::DecodeSession;
use crate::error::{DecoderError, Result};
use crate::isa::*;

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

pub struct Decoder {
    arch: Architecture,
}

impl Decoder {
    pub fn new(arch: Architecture) -> Self {
        Self { arch }
    }

    pub fn decode(
        &self,
        input: &[u8],
        address: u64,
    ) -> Result<Instruction> {
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

        self.parse_prefixes(
            &mut session,
            &mut prefixes,
            &mut rex,
            &mut rex2,
            &mut vex,
            &mut evex,
            &mut xop,
            &mut operand_size_override,
            &mut address_size_override,
            &mut segment_override,
            &mut has_rep,
            &mut has_repne,
            &mut has_lock,
            &mut segments,
        )?;

        let (eff_op_size, eff_addr_size) = self.determine_sizes(
            operand_size_override,
            address_size_override,
            rex.w || rex2.w || evex.w || xop.w,
        );

        segments.opcode.offset = session.cursor as u8;
        let mut is_two_byte = false;
        let mut is_three_byte = false;

        let opcode = if evex.present {
            let op = session.read_u8()?;
            is_two_byte = evex.m == 1 || evex.m == 2 || evex.m == 3;
            op
        } else if vex.present {
            let op = session.read_u8()?;
            is_two_byte = vex.m == 1 || vex.m == 2 || vex.m == 3;
            op
        } else if xop.present {
            let op = session.read_u8()?;
            is_two_byte = true;
            is_three_byte = xop.m == 0x09 || xop.m == 0x0A;
            op
        } else {
            let mut op = session.read_u8()?;
            if op == 0x0F {
                let next = session.peek_u8()?;
                if next == 0x38 || next == 0x3A || next == 0x1E {
                    is_three_byte = true;
                    let _map = session.read_u8()?;
                    op = session.read_u8()?;
                } else {
                    is_two_byte = true;
                    op = session.read_u8()?;
                }
            }
            op
        };

        segments.opcode.length = (session.cursor as u8) - segments.opcode.offset;

        let opcode_info = opcode_resolver::resolve_opcode(
            opcode,
            is_two_byte,
            is_three_byte,
            &session,
        )?;

        let mnemonic = opcode_info.mnemonic;
        let category = opcode_info.category;
        let extension = opcode_info.extension;
        let cf = opcode_info.control_flow;
        let has_modrm = opcode_info.has_modrm;

        let mut operands = Vec::new();

        let vector_len: u16 = if evex.present {
            match evex.l {
                0 => 128,
                1 => 256,
                2 => 512,
                _ => 128,
            }
        } else if vex.present {
            if vex.l { 256 } else { 128 }
        } else if xop.present {
            if xop.l { 256 } else { 128 }
        } else {
            0
        };

        if evex.present && (evex.v != 0 || evex.v_prime) {
            let v_reg_idx = evex.v | (if !evex.v_prime { 0x10 } else { 0 });
            let v_reg = register::decode_register(
                v_reg_idx,
                false,
                false,
                true,
                vector_len,
            );

            let opmask = if evex.aaa != 0 {
                Some(register::decode_register(
                    evex.aaa,
                    false,
                    false,
                    false,
                    0xFFFF,
                ))
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
            let v_reg = register::decode_register(
                v_idx,
                false,
                false,
                true,
                vector_len,
            );
            operands.push(Operand::Register {
                reg: v_reg,
                access: AccessType::Read,
                visibility: Visibility::Explicit,
                opmask: None,
                zeroing: false,
            });
        }

        if has_modrm {
            let reg_is_dst = match opcode {
                0x80..=0x83 => true,
                0x8A | 0x8B | 0x03 | 0x2B | 0x3B | 0x33 | 0x8D | 0x28 | 0x58 | 0xDC | 0xDE | 0x90 => true,
                _ => false,
            };

            let is_vec = vex.present
                || evex.present
                || xop.present
                || (is_three_byte && (opcode == 0xDC || opcode == 0xDE));

            let eff_vec_len = if is_vec && vector_len == 0 {
                128
            } else {
                vector_len
            };

            let (reg_op, rm_op) = modrm::decode_modrm_sib(
                &mut session,
                &rex,
                &rex2,
                &vex,
                &evex,
                eff_op_size,
                eff_addr_size,
                eff_vec_len,
                reg_is_dst,
                segment_override,
                &mut segments,
                self.arch,
            )?;

            if reg_is_dst {
                operands.push(reg_op);
                operands.push(rm_op);
            } else {
                operands.push(rm_op);
                operands.push(reg_op);
            }
        }

        let imm_start = session.cursor as u8;

        immediate::handle_immediate_operands(
            opcode,
            is_two_byte,
            &mut session,
            &rex,
            &rex2,
            &vex,
            &evex,
            &xop,
            eff_op_size,
            self.arch,
            &mut operands,
        )?;

        if session.cursor as u8 > imm_start {
            segments.immediate.offset = imm_start;
            segments.immediate.length = (session.cursor as u8) - imm_start;
        }

        let length = session.cursor as u8;
        let instruction_bytes = input[..session.cursor].to_vec();

        let has_xacquire = has_repne
            && has_lock
            && (mnemonic == Mnemonic::Add
                || mnemonic == Mnemonic::Sub
                || mnemonic == Mnemonic::Xor
                || mnemonic == Mnemonic::Mov);

        let has_xrelease = has_rep
            && has_lock
            && (mnemonic == Mnemonic::Add
                || mnemonic == Mnemonic::Sub
                || mnemonic == Mnemonic::Xor
                || mnemonic == Mnemonic::Mov);

        let mut instruction = Instruction {
            address,
            bytes: instruction_bytes,
            prefixes,
            mnemonic,
            operands,
            metadata: InstructionMetadata {
                length,
                architecture: self.arch,
                category,
                extension,
                control_flow: cf,
                flags: FlagEffect::default(),
                attributes: Attributes {
                    has_lock,
                    has_rep,
                    has_repne,
                    has_xacquire,
                    has_xrelease,
                    is_vector_op: vex.present || evex.present || xop.present,
                    ..Attributes::default()
                },
            },
            segments,
        };

        self.apply_semantic_metadata(&mut instruction);
        crate::validator::Validator::validate(&instruction)?;

        Ok(instruction)
    }

    fn determine_sizes(
        &self,
        op_override: bool,
        addr_override: bool,
        rex_w: bool,
    ) -> (OperandSize, OperandSize) {
        let op_size = if self.arch == Architecture::X64 {
            if rex_w {
                OperandSize::Size64
            } else if op_override {
                OperandSize::Size16
            } else {
                OperandSize::Size32
            }
        } else {
            if op_override {
                OperandSize::Size16
            } else {
                OperandSize::Size32
            }
        };

        let addr_size = if self.arch == Architecture::X64 {
            if addr_override {
                OperandSize::Size32
            } else {
                OperandSize::Size64
            }
        } else {
            if addr_override {
                OperandSize::Size16
            } else {
                OperandSize::Size32
            }
        };

        (op_size, addr_size)
    }

    fn parse_prefixes(
        &self,
        session: &mut DecodeSession,
        prefixes: &mut Vec<u8>,
        rex: &mut Rex,
        rex2: &mut Rex2,
        vex: &mut Vex,
        evex: &mut Evex,
        xop: &mut Xop,
        operand_size_override: &mut bool,
        address_size_override: &mut bool,
        segment_override: &mut Option<Segment>,
        has_rep: &mut bool,
        has_repne: &mut bool,
        has_lock: &mut bool,
        segments: &mut InstructionSegments,
    ) -> Result<()> {
        while session.cursor < session.input.len() {
            let byte = session.peek_u8()?;

            if byte == 0xC4 || byte == 0xC5 {
                let is_vex = if self.arch == Architecture::X64 {
                    true
                } else {
                    session.input
                        .get(session.cursor + 1)
                        .map_or(false, |&n| (n & 0xC0) == 0xC0)
                };

                if is_vex {
                    if !prefixes.is_empty() || rex.w || rex2.present {
                        return Err(DecoderError::CorruptStream {
                            offset: session.cursor,
                        });
                    }

                    segments.prefixes.offset = 0;

                    if byte == 0xC5 {
                        let b1 = session.read_u8()?;
                        let b2 = session.read_u8()?;
                        prefixes.push(b1);
                        prefixes.push(b2);
                        *vex = Vex {
                            present: true,
                            r: (b2 & 0x80) == 0,
                            v: (!b2 >> 3) & 0x0F,
                            l: (b2 & 0x04) != 0,
                            pp: b2 & 0x03,
                            m: 1,
                            ..Vex::default()
                        };
                    } else {
                        let b1 = session.read_u8()?;
                        let b2 = session.read_u8()?;
                        let b3 = session.read_u8()?;
                        prefixes.push(b1);
                        prefixes.push(b2);
                        prefixes.push(b3);
                        *vex = Vex {
                            present: true,
                            r: (b2 & 0x80) == 0,
                            x: (b2 & 0x40) == 0,
                            b: (b2 & 0x20) == 0,
                            m: b2 & 0x1F,
                            w: (b3 & 0x80) != 0,
                            v: (!b3 >> 3) & 0x0F,
                            l: (b3 & 0x04) != 0,
                            pp: b3 & 0x03,
                        };
                    }
                    return Ok(());
                }
            }

            if byte == 0x62 {
                let is_evex = if self.arch == Architecture::X64 {
                    true
                } else {
                    session.input
                        .get(session.cursor + 1)
                        .map_or(false, |&n| (n & 0xC0) == 0xC0)
                };

                if is_evex {
                    if !prefixes.is_empty() || rex.w || rex2.present {
                        return Err(DecoderError::CorruptStream {
                            offset: session.cursor,
                        });
                    }

                    segments.prefixes.offset = 0;
                    let p0 = session.read_u8()?;
                    let p1 = session.read_u8()?;
                    let p2 = session.read_u8()?;
                    let p3 = session.read_u8()?;

                    prefixes.push(p0);
                    prefixes.push(p1);
                    prefixes.push(p2);
                    prefixes.push(p3);

                    *evex = Evex {
                        present: true,
                        r: (p1 & 0x80) == 0,
                        x: (p1 & 0x40) == 0,
                        b: (p1 & 0x20) == 0,
                        r_prime: (p1 & 0x10) == 0,
                        m: p1 & 0x03,
                        w: (p2 & 0x80) != 0,
                        v: (!p2 >> 3) & 0x0F,
                        pp: p2 & 0x03,
                        z: (p3 & 0x80) != 0,
                        l: (p3 >> 5) & 0x03,
                        b_bit: (p3 & 0x10) != 0,
                        v_prime: (p3 & 0x08) == 0,
                        aaa: p3 & 0x07,
                        ..Evex::default()
                    };
                    return Ok(());
                }
            }

            if byte == 0x8F {
                let is_xop = if self.arch == Architecture::X64 {
                    true
                } else {
                    session.input
                        .get(session.cursor + 1)
                        .map_or(false, |&n| (n & 0xC0) == 0xC0)
                };

                if is_xop {
                    if let Some(&next) = session.input.get(session.cursor + 1) {
                        let m = next & 0x1F;
                        if m >= 0x08 && m <= 0x0A {
                            if !prefixes.is_empty() || rex.w || rex2.present {
                                return Err(DecoderError::CorruptStream {
                                    offset: session.cursor,
                                });
                            }

                            segments.prefixes.offset = 0;
                            let b1 = session.read_u8()?;
                            let b2 = session.read_u8()?;
                            let b3 = session.read_u8()?;

                            prefixes.push(b1);
                            prefixes.push(b2);
                            prefixes.push(b3);

                            *xop = Xop {
                                present: true,
                                r: (b2 & 0x80) == 0,
                                x: (b2 & 0x40) == 0,
                                b: (b2 & 0x20) == 0,
                                m,
                                w: (b3 & 0x80) != 0,
                                v: (!b3 >> 3) & 0x0F,
                                l: (b3 & 0x04) != 0,
                                pp: b3 & 0x03,
                            };
                            return Ok(());
                        }
                    }
                }
            }

            if byte == 0xD5 && self.arch == Architecture::X64 {
                let _p0 = session.read_u8()?;
                let p1 = session.read_u8()?;
                prefixes.push(0xD5);
                prefixes.push(p1);
                *rex2 = Rex2 {
                    present: true,
                    w: (p1 & 0x80) != 0,
                    r: (p1 & 0x40) != 0,
                    x: (p1 & 0x20) != 0,
                    b: (p1 & 0x10) != 0,
                    r_prime: (p1 & 0x04) != 0,
                    x_prime: (p1 & 0x02) != 0,
                    b_prime: (p1 & 0x01) != 0,
                };
                return Ok(());
            }

            if self.is_legacy_prefix(byte) {
                match byte {
                    PREFIX_OPERAND_SIZE => *operand_size_override = true,
                    PREFIX_ADDRESS_SIZE => *address_size_override = true,
                    PREFIX_LOCK => *has_lock = true,
                    PREFIX_REPE => *has_rep = true,
                    PREFIX_REPNE => *has_repne = true,
                    PREFIX_CS_OVERRIDE => *segment_override = Some(Segment::CS),
                    PREFIX_DS_OVERRIDE => *segment_override = Some(Segment::DS),
                    PREFIX_ES_OVERRIDE => *segment_override = Some(Segment::ES),
                    PREFIX_SS_OVERRIDE => *segment_override = Some(Segment::SS),
                    PREFIX_FS_OVERRIDE => *segment_override = Some(Segment::FS),
                    PREFIX_GS_OVERRIDE => *segment_override = Some(Segment::GS),
                    _ => {}
                }
                prefixes.push(session.read_u8()?);
                continue;
            }

            if self.arch == Architecture::X64 && (0x40..=0x4F).contains(&byte) {
                let b = session.read_u8()?;
                *rex = Rex {
                    w: (b & 0x08) != 0,
                    r: (b & 0x04) != 0,
                    x: (b & 0x02) != 0,
                    b: (b & 0x01) != 0,
                };
                prefixes.push(b);
                continue;
            }

            break;
        }

        Ok(())
    }

    fn is_legacy_prefix(&self, byte: u8) -> bool {
        match byte {
            PREFIX_LOCK
            | PREFIX_REPNE
            | PREFIX_REPE
            | PREFIX_CS_OVERRIDE
            | PREFIX_SS_OVERRIDE
            | PREFIX_DS_OVERRIDE
            | PREFIX_ES_OVERRIDE
            | PREFIX_FS_OVERRIDE
            | PREFIX_GS_OVERRIDE
            | PREFIX_OPERAND_SIZE
            | PREFIX_ADDRESS_SIZE => true,
            _ => false,
        }
    }

    fn apply_semantic_metadata(&self, insn: &mut Instruction) {
        branch::calculate_branch_targets(insn, self.arch);
        implicit::add_implicit_operands(insn, self.arch);
        flags::populate_flag_effects(insn);
        attributes::populate_attributes(insn);
    }
}