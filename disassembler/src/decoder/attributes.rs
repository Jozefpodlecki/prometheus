use crate::isa::{Instruction, Mnemonic, InstructionCategory};

pub fn populate_attributes(insn: &mut Instruction) {
    let attr = &mut insn.metadata.attributes;
    match insn.mnemonic {
        Mnemonic::Push | Mnemonic::Pop | Mnemonic::Ret | Mnemonic::Call | Mnemonic::Pushfq | Mnemonic::Popfq => {
            attr.is_stack_op = true;
        }
        Mnemonic::Syscall | Mnemonic::Int => {
            attr.is_privileged = true;
        }
        Mnemonic::Movs => {
            attr.is_string_op = true;
        }
        _ => {}
    }
    if insn.metadata.category == InstructionCategory::System {
        attr.is_privileged = true;
    }
}