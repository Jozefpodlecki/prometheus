use crate::isa::flags::*;
use crate::isa::{FlagEffect, Instruction, Mnemonic};

pub fn populate_flag_effects(insn: &mut Instruction) {
    let (tested, modified, set, cleared, undefined) = match insn.mnemonic {
        Mnemonic::Add | Mnemonic::Sub | Mnemonic::Cmp | Mnemonic::Test | Mnemonic::Neg | Mnemonic::Xadd => {
            (0, CF | PF | AF | ZF | SF | OF, 0, 0, 0)
        }
        Mnemonic::Adc | Mnemonic::Sbb => {
            (CF, CF | PF | AF | ZF | SF | OF, 0, 0, 0)
        }
        Mnemonic::Inc | Mnemonic::Dec => {
            (0, PF | AF | ZF | SF | OF, 0, 0, 0)
        }
        Mnemonic::Xor | Mnemonic::And | Mnemonic::Or => {
            (0, PF | ZF | SF, 0, CF | OF, 0)
        }
        Mnemonic::Not | Mnemonic::Mov | Mnemonic::Movs | Mnemonic::Lea | Mnemonic::Push | Mnemonic::Pop | Mnemonic::Xchg => {
            (0, 0, 0, 0, 0)
        }
        Mnemonic::Clc => (0, 0, 0, CF, 0),
        Mnemonic::Stc => (0, 0, CF, 0, 0),
        Mnemonic::Cld => (0, 0, 0, DF, 0),
        Mnemonic::Std => (0, 0, DF, 0, 0),
        Mnemonic::Pushfq => (0xFFFFFFFF, 0, 0, 0, 0),
        Mnemonic::Popfq => (0, 0xFFFFFFFF, 0, 0, 0),
        Mnemonic::Jz | Mnemonic::Jnz | Mnemonic::Js | Mnemonic::Jns | Mnemonic::Jo | Mnemonic::Jno | Mnemonic::Jb | Mnemonic::Jae => {
            let t = match insn.mnemonic {
                Mnemonic::Jz | Mnemonic::Jnz => ZF,
                Mnemonic::Js | Mnemonic::Jns => SF,
                Mnemonic::Jo | Mnemonic::Jno => OF,
                Mnemonic::Jb | Mnemonic::Jae => CF,
                _ => 0,
            };
            (t, 0, 0, 0, 0)
        }
        Mnemonic::Btc | Mnemonic::Btr | Mnemonic::Bts => (0, CF, 0, 0, 0),
        _ => {
            let _auto_fx = crate::autogen_isa::auto_flag_effects(crate::autogen_isa::AutoMnemonic::Unknown);
            (0, 0, 0, 0, 0)
        }
    };
    insn.metadata.flags = FlagEffect {
        tested,
        modified,
        set,
        cleared,
        undefined,
    };
}