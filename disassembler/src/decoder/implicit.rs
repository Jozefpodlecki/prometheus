use crate::isa::{AccessType, Architecture, Instruction, Mnemonic, Operand, Register, Visibility};

pub fn add_implicit_operands(insn: &mut Instruction, arch: Architecture) {
    let stack_ptr = if arch == Architecture::X64 {
        Register::Rsp
    } else {
        Register::Esp
    };

    match insn.mnemonic {
        Mnemonic::Ret => {
            insn.operands.push(Operand::Register {
                reg: stack_ptr,
                access: AccessType::ReadWrite,
                visibility: Visibility::Implicit,
                opmask: None,
                zeroing: false,
            });
        }
        Mnemonic::Call | Mnemonic::Push | Mnemonic::Pop | Mnemonic::Pushfq | Mnemonic::Popfq => {
            insn.operands.push(Operand::Register {
                reg: stack_ptr,
                access: AccessType::ReadWrite,
                visibility: Visibility::Implicit,
                opmask: None,
                zeroing: false,
            });
        }
        Mnemonic::Syscall => {
            insn.operands.push(Operand::Register {
                reg: Register::Rcx,
                access: AccessType::Write,
                visibility: Visibility::Implicit,
                opmask: None,
                zeroing: false,
            });
            insn.operands.push(Operand::Register {
                reg: Register::R11,
                access: AccessType::Write,
                visibility: Visibility::Implicit,
                opmask: None,
                zeroing: false,
            });
        }
        Mnemonic::Movs => {
            insn.operands.push(Operand::Register {
                reg: Register::Rsi,
                access: AccessType::ReadWrite,
                visibility: Visibility::Implicit,
                opmask: None,
                zeroing: false,
            });
            insn.operands.push(Operand::Register {
                reg: Register::Rdi,
                access: AccessType::ReadWrite,
                visibility: Visibility::Implicit,
                opmask: None,
                zeroing: false,
            });
            if insn.metadata.attributes.has_rep || insn.metadata.attributes.has_repne {
                insn.operands.push(Operand::Register {
                    reg: Register::Rcx,
                    access: AccessType::ReadWrite,
                    visibility: Visibility::Implicit,
                    opmask: None,
                    zeroing: false,
                });
            }
        }
        _ => {}
    }
}