// decoder/opcode_resolver.rs
use crate::decoder::session::DecodeSession;
use crate::error::{DecoderError, Result};
use crate::isa::{ControlFlow, InstructionCategory, IsaExtension, Mnemonic};

pub struct OpcodeResult {
    pub mnemonic: Mnemonic,
    pub category: InstructionCategory,
    pub extension: IsaExtension,
    pub control_flow: ControlFlow,
    pub has_modrm: bool,
}

pub fn resolve_opcode(
    opcode: u8,
    is_two_byte: bool,
    is_three_byte: bool,
    session: &DecodeSession,
) -> Result<OpcodeResult> {
    if is_three_byte {
        resolve_three_byte(opcode, session)
    } else if is_two_byte {
        resolve_two_byte(opcode, session)
    } else {
        resolve_one_byte(opcode, session)
    }
}

fn resolve_three_byte(opcode: u8, session: &DecodeSession) -> Result<OpcodeResult> {
    match opcode {
        0xDC => Ok(OpcodeResult {
            mnemonic: Mnemonic::Aesenc,
            category: InstructionCategory::Arithmetic,
            extension: IsaExtension::AES,
            control_flow: ControlFlow::None,
            has_modrm: true,
        }),
        0xDE => Ok(OpcodeResult {
            mnemonic: Mnemonic::Aesdec,
            category: InstructionCategory::Arithmetic,
            extension: IsaExtension::AES,
            control_flow: ControlFlow::None,
            has_modrm: true,
        }),
        0xFA => Ok(OpcodeResult {
            mnemonic: Mnemonic::Endbr64,
            category: InstructionCategory::ControlFlow,
            extension: IsaExtension::CET,
            control_flow: ControlFlow::None,
            has_modrm: false,
        }),
        0x90 => Ok(OpcodeResult {
            mnemonic: Mnemonic::Vprotb,
            category: InstructionCategory::Arithmetic,
            extension: IsaExtension::XOP,
            control_flow: ControlFlow::None,
            has_modrm: true,
        }),
        _ => {
            if opcode == 0x1E {
                let next = session.peek_u8().unwrap_or_default();
                if next == 0xFA {
                    return Ok(OpcodeResult {
                        mnemonic: Mnemonic::Endbr64,
                        category: InstructionCategory::ControlFlow,
                        extension: IsaExtension::CET,
                        control_flow: ControlFlow::None,
                        has_modrm: false,
                    });
                }
            }
            Err(DecoderError::UnsupportedEncoding {
                offset: session.cursor,
            })
        }
    }
}

fn resolve_two_byte(opcode: u8, session: &DecodeSession) -> Result<OpcodeResult> {
    match opcode {
        0x05 => Ok(OpcodeResult {
            mnemonic: Mnemonic::Syscall,
            category: InstructionCategory::System,
            extension: IsaExtension::Base,
            control_flow: ControlFlow::Syscall,
            has_modrm: false,
        }),
        0x84 => Ok(OpcodeResult {
            mnemonic: Mnemonic::Jz,
            category: InstructionCategory::ControlFlow,
            extension: IsaExtension::Base,
            control_flow: ControlFlow::ConditionalBranch,
            has_modrm: false,
        }),
        0x85 => Ok(OpcodeResult {
            mnemonic: Mnemonic::Jnz,
            category: InstructionCategory::ControlFlow,
            extension: IsaExtension::Base,
            control_flow: ControlFlow::ConditionalBranch,
            has_modrm: false,
        }),
        0x80..=0x8F => Ok(OpcodeResult {
            mnemonic: Mnemonic::Jmp,
            category: InstructionCategory::ControlFlow,
            extension: IsaExtension::Base,
            control_flow: ControlFlow::ConditionalBranch,
            has_modrm: false,
        }),
        0x28 => Ok(OpcodeResult {
            mnemonic: Mnemonic::Vmovaps,
            category: InstructionCategory::Miscellaneous,
            extension: IsaExtension::AVX,
            control_flow: ControlFlow::None,
            has_modrm: true,
        }),
        0x58 => Ok(OpcodeResult {
            mnemonic: Mnemonic::Vaddps,
            category: InstructionCategory::Arithmetic,
            extension: IsaExtension::AVX,
            control_flow: ControlFlow::None,
            has_modrm: true,
        }),
        _ => {
            let auto_m = crate::autogen_isa::auto_resolve_opcode_0f(opcode);
            if auto_m != crate::autogen_isa::AutoMnemonic::Unknown {
                Ok(OpcodeResult {
                    mnemonic: Mnemonic::Auto(auto_m),
                    category: InstructionCategory::Miscellaneous,
                    extension: IsaExtension::Base,
                    control_flow: ControlFlow::None,
                    has_modrm: true,
                })
            } else {
                Err(DecoderError::InvalidOpcode {
                    offset: session.cursor,
                    opcode,
                })
            }
        }
    }
}

fn resolve_one_byte(opcode: u8, session: &DecodeSession) -> Result<OpcodeResult> {
    match opcode {
        0x80..=0x83 => Ok(OpcodeResult {
            mnemonic: Mnemonic::Unknown,
            category: InstructionCategory::Arithmetic,
            extension: IsaExtension::Base,
            control_flow: ControlFlow::None,
            has_modrm: true,
        }),
        0xD8..=0xDF => Ok(OpcodeResult {
            mnemonic: Mnemonic::Fadd,
            category: InstructionCategory::Arithmetic,
            extension: IsaExtension::Base,
            control_flow: ControlFlow::None,
            has_modrm: true,
        }),
        0x90 => Ok(OpcodeResult {
            mnemonic: Mnemonic::Nop,
            category: InstructionCategory::Miscellaneous,
            extension: IsaExtension::Base,
            control_flow: ControlFlow::None,
            has_modrm: false,
        }),
        0xA4 | 0xA5 => Ok(OpcodeResult {
            mnemonic: Mnemonic::Movs,
            category: InstructionCategory::DataTransfer,
            extension: IsaExtension::Base,
            control_flow: ControlFlow::None,
            has_modrm: false,
        }),
        0xC3 => Ok(OpcodeResult {
            mnemonic: Mnemonic::Ret,
            category: InstructionCategory::ControlFlow,
            extension: IsaExtension::Base,
            control_flow: ControlFlow::Return,
            has_modrm: false,
        }),
        0xFF => Ok(OpcodeResult {
            mnemonic: Mnemonic::Call,
            category: InstructionCategory::ControlFlow,
            extension: IsaExtension::Base,
            control_flow: ControlFlow::Call,
            has_modrm: true,
        }),
        0x88 | 0x89 | 0x8A | 0x8B => Ok(OpcodeResult {
            mnemonic: Mnemonic::Mov,
            category: InstructionCategory::DataTransfer,
            extension: IsaExtension::Base,
            control_flow: ControlFlow::None,
            has_modrm: true,
        }),
        0x84 | 0x85 => Ok(OpcodeResult {
            mnemonic: Mnemonic::Test,
            category: InstructionCategory::Arithmetic,
            extension: IsaExtension::Base,
            control_flow: ControlFlow::None,
            has_modrm: true,
        }),
        0x8D => Ok(OpcodeResult {
            mnemonic: Mnemonic::Lea,
            category: InstructionCategory::DataTransfer,
            extension: IsaExtension::Base,
            control_flow: ControlFlow::None,
            has_modrm: true,
        }),
        0x01 | 0x03 => Ok(OpcodeResult {
            mnemonic: Mnemonic::Add,
            category: InstructionCategory::Arithmetic,
            extension: IsaExtension::Base,
            control_flow: ControlFlow::None,
            has_modrm: true,
        }),
        0x29 | 0x2B => Ok(OpcodeResult {
            mnemonic: Mnemonic::Sub,
            category: InstructionCategory::Arithmetic,
            extension: IsaExtension::Base,
            control_flow: ControlFlow::None,
            has_modrm: true,
        }),
        0x39 | 0x3B => Ok(OpcodeResult {
            mnemonic: Mnemonic::Cmp,
            category: InstructionCategory::Arithmetic,
            extension: IsaExtension::Base,
            control_flow: ControlFlow::None,
            has_modrm: true,
        }),
        0x31 | 0x33 => Ok(OpcodeResult {
            mnemonic: Mnemonic::Xor,
            category: InstructionCategory::Arithmetic,
            extension: IsaExtension::Base,
            control_flow: ControlFlow::None,
            has_modrm: true,
        }),
        0xB8..=0xBF => Ok(OpcodeResult {
            mnemonic: Mnemonic::Mov,
            category: InstructionCategory::DataTransfer,
            extension: IsaExtension::Base,
            control_flow: ControlFlow::None,
            has_modrm: false,
        }),
        0x50..=0x57 => Ok(OpcodeResult {
            mnemonic: Mnemonic::Push,
            category: InstructionCategory::DataTransfer,
            extension: IsaExtension::Base,
            control_flow: ControlFlow::None,
            has_modrm: false,
        }),
        0x58..=0x5F => Ok(OpcodeResult {
            mnemonic: Mnemonic::Pop,
            category: InstructionCategory::DataTransfer,
            extension: IsaExtension::Base,
            control_flow: ControlFlow::None,
            has_modrm: false,
        }),
        0x9C => Ok(OpcodeResult {
            mnemonic: Mnemonic::Pushfq,
            category: InstructionCategory::DataTransfer,
            extension: IsaExtension::Base,
            control_flow: ControlFlow::None,
            has_modrm: false,
        }),
        0x9D => Ok(OpcodeResult {
            mnemonic: Mnemonic::Popfq,
            category: InstructionCategory::DataTransfer,
            extension: IsaExtension::Base,
            control_flow: ControlFlow::None,
            has_modrm: false,
        }),
        0xF8 => Ok(OpcodeResult {
            mnemonic: Mnemonic::Clc,
            category: InstructionCategory::Miscellaneous,
            extension: IsaExtension::Base,
            control_flow: ControlFlow::None,
            has_modrm: false,
        }),
        0xF9 => Ok(OpcodeResult {
            mnemonic: Mnemonic::Stc,
            category: InstructionCategory::Miscellaneous,
            extension: IsaExtension::Base,
            control_flow: ControlFlow::None,
            has_modrm: false,
        }),
        0xFC => Ok(OpcodeResult {
            mnemonic: Mnemonic::Cld,
            category: InstructionCategory::Miscellaneous,
            extension: IsaExtension::Base,
            control_flow: ControlFlow::None,
            has_modrm: false,
        }),
        0xFD => Ok(OpcodeResult {
            mnemonic: Mnemonic::Std,
            category: InstructionCategory::Miscellaneous,
            extension: IsaExtension::Base,
            control_flow: ControlFlow::None,
            has_modrm: false,
        }),
        0xCD => Ok(OpcodeResult {
            mnemonic: Mnemonic::Int,
            category: InstructionCategory::System,
            extension: IsaExtension::Base,
            control_flow: ControlFlow::Interrupt,
            has_modrm: false,
        }),
        0xE8 => Ok(OpcodeResult {
            mnemonic: Mnemonic::Call,
            category: InstructionCategory::ControlFlow,
            extension: IsaExtension::Base,
            control_flow: ControlFlow::Call,
            has_modrm: false,
        }),
        0xE9 => Ok(OpcodeResult {
            mnemonic: Mnemonic::Jmp,
            category: InstructionCategory::ControlFlow,
            extension: IsaExtension::Base,
            control_flow: ControlFlow::UnconditionalBranch,
            has_modrm: false,
        }),
        _ => {
            let auto_m = crate::autogen_isa::auto_resolve_opcode(opcode);
            if auto_m != crate::autogen_isa::AutoMnemonic::Unknown {
                Ok(OpcodeResult {
                    mnemonic: Mnemonic::Auto(auto_m),
                    category: InstructionCategory::Miscellaneous,
                    extension: IsaExtension::Base,
                    control_flow: ControlFlow::None,
                    has_modrm: true,
                })
            } else {
                Err(DecoderError::InvalidOpcode {
                    offset: session.cursor,
                    opcode,
                })
            }
        }
    }
}