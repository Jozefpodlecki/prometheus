use crate::decoder::session::DecodeSession;
use crate::decoder::register;
use crate::decoder::types::*;
use crate::error::{DecoderError, Result};
use crate::isa::*;

pub fn handle_immediate_operands(
    opcode: u8,
    is_two_byte: bool,
    session: &mut DecodeSession,
    rex: &Rex,
    rex2: &Rex2,
    vex: &Vex,
    evex: &Evex,
    xop: &Xop,
    eff_op_size: OperandSize,
    arch: Architecture,
    operands: &mut Vec<Operand>,
) -> Result<()> {
    if is_two_byte {
        if (0x80..=0x8F).contains(&opcode) {
            operands.push(Operand::Immediate {
                imm: Immediate::I32(session.read_i32()?),
                visibility: Visibility::Explicit,
            });
        }
    } else {
        match opcode {
            0xB8..=0xBF => {
                let reg_idx = opcode & 0x07;
                let reg = register::decode_register(
                    reg_idx,
                    rex.b || rex2.b || vex.b || evex.b || xop.b,
                    rex2.b_prime,
                    eff_op_size == OperandSize::Size64 || rex2.w || evex.w || xop.w,
                    0,
                );
                operands.push(Operand::Register {
                    reg,
                    access: AccessType::Write,
                    visibility: Visibility::Explicit,
                    opmask: None,
                    zeroing: false,
                });
                if eff_op_size == OperandSize::Size64 || rex2.w || evex.w || xop.w {
                    operands.push(Operand::Immediate {
                        imm: Immediate::U64(session.read_u64()?),
                        visibility: Visibility::Explicit,
                    });
                } else if eff_op_size == OperandSize::Size16 { 
                    operands.push(Operand::Immediate { 
                        imm: Immediate::U16(session.read_u16()?), 
                        visibility: Visibility::Explicit 
                    });
                } else {
                    operands.push(Operand::Immediate {
                        imm: Immediate::U32(session.read_u32()?),
                        visibility: Visibility::Explicit,
                    });
                }
            }
            0x50..=0x57 => {
                let reg_idx = opcode & 0x07;
                let reg = register::decode_register(
                    reg_idx,
                    rex.b || rex2.b || vex.b || evex.b || xop.b,
                    rex2.b_prime,
                    arch == Architecture::X64,
                    0,
                );
                operands.push(Operand::Register {
                    reg,
                    access: AccessType::Read,
                    visibility: Visibility::Explicit,
                    opmask: None,
                    zeroing: false,
                });
            }
            0x58..=0x5F => {
                let reg_idx = opcode & 0x07;
                let reg = register::decode_register(
                    reg_idx,
                    rex.b || rex2.b || vex.b || evex.b || xop.b,
                    rex2.b_prime,
                    arch == Architecture::X64,
                    0,
                );
                operands.push(Operand::Register {
                    reg,
                    access: AccessType::Write,
                    visibility: Visibility::Explicit,
                    opmask: None,
                    zeroing: false,
                });
            }
            0xCD => {
                operands.push(Operand::Immediate {
                    imm: Immediate::U8(session.read_u8()?),
                    visibility: Visibility::Explicit,
                });
            }
            0xE8 | 0xE9 => {
                operands.push(Operand::Immediate {
                    imm: Immediate::I32(session.read_i32()?),
                    visibility: Visibility::Explicit,
                });
            }
            0xA4 | 0xA5 => {}
            _ => {}
        }
    }
    Ok(())
}