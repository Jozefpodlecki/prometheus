use crate::isa::{Architecture, ControlFlow, Immediate, Instruction, Operand, Register};

pub fn calculate_branch_targets(insn: &mut Instruction, arch: Architecture) {
    let is_branch = matches!(
        insn.metadata.control_flow,
        ControlFlow::ConditionalBranch | ControlFlow::UnconditionalBranch | ControlFlow::Call
    );

    if is_branch {
        for op in &mut insn.operands {
            if let Operand::Immediate { imm, .. } = op {
                if let Immediate::I32(rel) = *imm {
                    let target = insn
                        .address
                        .wrapping_add(insn.metadata.length as u64)
                        .wrapping_add(rel as i64 as u64);
                    *imm = Immediate::U64(target);
                }
            }
        }
    }

    if arch == Architecture::X64 {
        for op in &mut insn.operands {
            if let Operand::Memory { mem, .. } = op {
                if mem.base == Some(Register::Rip) {
                    let target = insn
                        .address
                        .wrapping_add(insn.metadata.length as u64)
                        .wrapping_add(mem.displacement as u64);
                    mem.absolute_address = Some(target);
                }
            }
        }
    }
}