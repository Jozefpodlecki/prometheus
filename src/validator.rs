use crate::error::{DecoderError, Result};
use crate::isa::{Instruction, Architecture, Mnemonic, Operand};

/*
** Validator logic for instruction sequence verification.
** This work is dedicated to the public domain under CC0 1.0 Universal.
*/
pub struct Validator;

impl Validator {
    /*
    ** Main entry point for instruction validation. It enforces global ISA
    ** limits (like the 15-byte maximum) before dispatching to architecture-
    ** specific validation routines.
    */
    pub fn validate(instruction: &Instruction) -> Result<()> {
        /*
        ** x86 instructions are limited to 15 bytes. This limit includes all
        ** prefixes, opcodes, ModRM/SIB bytes, and displacements/immediates.
        ** Any sequence exceeding this is considered invalid.
        */
        if instruction.metadata.length > 15 {
            return Err(DecoderError::InstructionTooLong { offset: instruction.metadata.length as usize });
        }

        if instruction.bytes.len() != instruction.metadata.length as usize {
            return Err(DecoderError::CorruptStream { offset: instruction.metadata.length as usize });
        }

        match instruction.metadata.architecture {
            Architecture::X64 => Self::validate_x64(instruction),
            Architecture::X86 => Self::validate_x86(instruction),
        }
    }

    /*
    ** x64-specific validation logic.
    **
    ** In 64-bit mode, several legacy constraints are relaxed, while others
    ** (like REX prefix placement) are strictly enforced. We also check for
    ** the validity of the LOCK prefix and segment overrides.
    */
    fn validate_x64(instruction: &Instruction) -> Result<()> {
        Self::check_lock_prefix(instruction)?;
        Self::check_prefix_integrity(instruction)?;
        
        Ok(())
    }

    /*
    ** x86-specific legacy validation logic.
    **
    ** 32-bit mode allows for certain prefix combinations that are either
    ** ignored or behave differently in 64-bit mode.
    */
    fn validate_x86(instruction: &Instruction) -> Result<()> {
        Self::check_lock_prefix(instruction)?;
        
        Ok(())
    }

    /*
    ** The LOCK prefix (0xF0) is restricted to a specific set of instructions
    ** that perform atomic read-modify-write operations on memory.
    **
    ** If LOCK is applied to an instruction that does not modify memory, or
    ** to an opcode not in the approved list, the processor generates a #UD.
    */
    fn check_lock_prefix(instruction: &Instruction) -> Result<()> {
        let has_lock = instruction.prefixes.iter().any(|&p| p == 0xF0);
        if !has_lock {
            return Ok(());
        }

        /*
        ** Verify the opcode is allowed to be locked.
        */
        let is_lockable_mnemonic = matches!(instruction.mnemonic,
            Mnemonic::Add | Mnemonic::Adc | Mnemonic::And | Mnemonic::Btc | Mnemonic::Btr |
            Mnemonic::Bts | Mnemonic::Cmpxchg | Mnemonic::Dec | Mnemonic::Inc |
            Mnemonic::Neg | Mnemonic::Not | Mnemonic::Or | Mnemonic::Sbb |
            Mnemonic::Sub | Mnemonic::Xor | Mnemonic::Xadd | Mnemonic::Xchg
        );

        if !is_lockable_mnemonic {
            return Err(DecoderError::InvalidOpcode { offset: instruction.metadata.length as usize, opcode: 0xF0 });
        }

        /*
        ** LOCK is only valid if the first operand is a memory operand.
        */
        let has_memory_dest = instruction.operands.first().is_some_and(|op| {
            matches!(op, Operand::Memory { .. })
        });

        if !has_memory_dest {
            return Err(DecoderError::InvalidOpcode { offset: instruction.metadata.length as usize, opcode: 0xF0 });
        }

        Ok(())
    }

    /*
    ** Ensures that prefixes are used in a coherent manner.
    **
    ** Specifically, we check that:
    ** 1. REX prefixes (0x40-0x4F) only appear in 64-bit mode.
    ** 2. REX prefixes must be placed immediately before the opcode.
    ** 3. There are no conflicting segment overrides.
    */
    fn check_prefix_integrity(instruction: &Instruction) -> Result<()> {
        let mut rex_index: Option<usize> = None;
        let mut rep_count = 0;
        let mut lock_count = 0;
        let mut segment_override_count = 0;

        for (i, &p) in instruction.prefixes.iter().enumerate() {
            if (0x40..=0x4F).contains(&p) {
                rex_index = Some(i);
            }
            match p {
                0xF0 => lock_count += 1,
                0xF2 | 0xF3 => rep_count += 1,
                0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65 => segment_override_count += 1,
                _ => {}
            }
        }
        
        /*
        ** Reject instructions with duplicate/conflicting prefixes that while technically 
        ** decodable on some microarchitectures, represent malformed or malicious byte streams.
        ** This prevents analysis engines from getting desynchronized from the actual CPU.
        */
        if lock_count > 1 || rep_count > 1 || segment_override_count > 1 {
            return Err(DecoderError::CorruptStream { offset: instruction.metadata.length as usize });
        }

        /*
        ** If a REX prefix is present, it must be the very last prefix in the
        ** sequence, appearing just before the opcode bytes. Any prefix
        ** following REX is considered part of the opcode or an error.
        */
        if let Some(idx) = rex_index {
            if idx != instruction.prefixes.len() - 1 {
                return Err(DecoderError::CorruptStream { offset: idx });
            }
        }

        Ok(())
    }
}
