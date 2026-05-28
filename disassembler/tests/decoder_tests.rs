use prometheus_disassembler::decoder::session::DecodeSession;
use prometheus_disassembler::decoder::opcode_resolver::resolve_opcode;
use prometheus_disassembler::decoder::register::decode_register;
use prometheus_disassembler::isa::*;
use prometheus_disassembler::Decoder;

#[cfg(test)]
mod session_tests {
    use super::*;

    #[test]
    fn test_read_u8() {
        let data = vec![0x90, 0xC3];
        let mut session = DecodeSession::new(&data);
        
        assert_eq!(session.read_u8().unwrap(), 0x90);
        assert_eq!(session.read_u8().unwrap(), 0xC3);
        assert!(session.read_u8().is_err());
    }

    #[test]
    fn test_peek_u8() {
        let data = vec![0x90, 0xC3];
        let mut session = DecodeSession::new(&data);
        
        assert_eq!(session.peek_u8().unwrap(), 0x90);
        assert_eq!(session.read_u8().unwrap(), 0x90);
        assert_eq!(session.peek_u8().unwrap(), 0xC3);
    }

    #[test]
    fn test_read_u32() {
        let data = vec![0x78, 0x56, 0x34, 0x12];
        let mut session = DecodeSession::new(&data);
        
        assert_eq!(session.read_u32().unwrap(), 0x12345678);
    }

    #[test]
    fn test_read_u64() {
        let data = vec![0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01];
        let mut session = DecodeSession::new(&data);
        
        assert_eq!(session.read_u64().unwrap(), 0x0123456789ABCDEF);
    }
}

#[cfg(test)]
mod opcode_tests {
    use super::*;

    #[test]
    fn test_resolve_one_byte_nop() {
        let data = vec![0x90];
        let session = DecodeSession::new(&data);
        let result = resolve_opcode(0x90, false, false, &session).unwrap();
        
        assert_eq!(result.mnemonic, Mnemonic::Nop);
        assert_eq!(result.has_modrm, false);
    }

    #[test]
    fn test_resolve_one_byte_ret() {
        let data = vec![0xC3];
        let session = DecodeSession::new(&data);
        let result = resolve_opcode(0xC3, false, false, &session).unwrap();
        
        assert_eq!(result.mnemonic, Mnemonic::Ret);
        assert_eq!(result.control_flow, ControlFlow::Return);
    }

    #[test]
    fn test_resolve_one_byte_call() {
        let data = vec![0xE8];
        let session = DecodeSession::new(&data);
        let result = resolve_opcode(0xE8, false, false, &session).unwrap();
        
        assert_eq!(result.mnemonic, Mnemonic::Call);
        assert_eq!(result.control_flow, ControlFlow::Call);
    }

    #[test]
    fn test_resolve_one_byte_jmp() {
        let data = vec![0xE9];
        let session = DecodeSession::new(&data);
        let result = resolve_opcode(0xE9, false, false, &session).unwrap();
        
        assert_eq!(result.mnemonic, Mnemonic::Jmp);
        assert_eq!(result.control_flow, ControlFlow::UnconditionalBranch);
    }

    #[test]
    fn test_resolve_one_byte_mov() {
        let data = vec![0x88];
        let session = DecodeSession::new(&data);
        let result = resolve_opcode(0x88, false, false, &session).unwrap();
        
        assert_eq!(result.mnemonic, Mnemonic::Mov);
        assert_eq!(result.has_modrm, true);
    }

    #[test]
    fn test_resolve_two_byte_syscall() {
        let data = vec![0x0F, 0x05];
        let session = DecodeSession::new(&data);
        let result = resolve_opcode(0x05, true, false, &session).unwrap();
        
        assert_eq!(result.mnemonic, Mnemonic::Syscall);
        assert_eq!(result.control_flow, ControlFlow::Syscall);
    }

    #[test]
    fn test_resolve_two_byte_jz() {
        let data = vec![0x0F, 0x84];
        let session = DecodeSession::new(&data);
        let result = resolve_opcode(0x84, true, false, &session).unwrap();
        
        assert_eq!(result.mnemonic, Mnemonic::Jz);
        assert_eq!(result.control_flow, ControlFlow::ConditionalBranch);
    }

    #[test]
    fn test_resolve_three_byte_aesenc() {
        let data = vec![0x0F, 0x38, 0xDC];
        let session = DecodeSession::new(&data);
        let result = resolve_opcode(0xDC, false, true, &session).unwrap();
        
        assert_eq!(result.mnemonic, Mnemonic::Aesenc);
        assert_eq!(result.extension, IsaExtension::AES);
    }
}

#[cfg(test)]
mod register_tests {
    use super::*;

    #[test]
    fn test_decode_gpr64() {
        let reg = decode_register(0, false, false, true, 0);
        assert_eq!(reg, Register::Rax);
        
        let reg = decode_register(1, false, false, true, 0);
        assert_eq!(reg, Register::Rcx);
        
        let reg = decode_register(7, false, false, true, 0);
        assert_eq!(reg, Register::Rdi);
    }

    #[test]
    fn test_decode_gpr64_with_ext1() {
        let reg = decode_register(0, true, false, true, 0);
        assert_eq!(reg, Register::R8);
        
        let reg = decode_register(1, true, false, true, 0);
        assert_eq!(reg, Register::R9);
    }

    #[test]
    fn test_decode_gpr32() {
        let reg = decode_register(0, false, false, false, 0);
        assert_eq!(reg, Register::Eax);
        
        let reg = decode_register(1, false, false, false, 0);
        assert_eq!(reg, Register::Ecx);
    }

    #[test]
    fn test_decode_xmm() {
        let reg = decode_register(0, false, false, false, 128);
        assert_eq!(reg, Register::Xmm0);
        
        let reg = decode_register(1, false, false, false, 128);
        assert_eq!(reg, Register::Xmm1);
        
        let reg = decode_register(8, false, false, false, 128);
        assert_eq!(reg, Register::Xmm8);
    }

    #[test]
    fn test_decode_ymm() {
        let reg = decode_register(0, false, false, false, 256);
        assert_eq!(reg, Register::Ymm0);
        
        let reg = decode_register(1, false, false, false, 256);
        assert_eq!(reg, Register::Ymm1);
    }

    #[test]
    fn test_decode_zmm() {
        let reg = decode_register(0, false, false, false, 512);
        assert_eq!(reg, Register::Zmm0);
        
        let reg = decode_register(1, false, false, false, 512);
        assert_eq!(reg, Register::Zmm1);
    }

    #[test]
    fn test_decode_opmask() {
        let reg = decode_register(0, false, false, false, 0xFFFF);
        assert_eq!(reg, Register::K0);
        
        let reg = decode_register(1, false, false, false, 0xFFFF);
        assert_eq!(reg, Register::K1);
    }

    #[test]
    fn test_decode_fpu() {
        let reg = decode_register(0, false, false, false, 0xFFFE);
        assert_eq!(reg, Register::St0);
        
        let reg = decode_register(1, false, false, false, 0xFFFE);
        assert_eq!(reg, Register::St1);
    }
}

#[cfg(test)]
mod decoder_integration_tests {
    use super::*;

    #[test]
    fn test_decode_nop() {
        let decoder = Decoder::new(Architecture::X64);
        let data = vec![0x90];
        let insn = decoder.decode(&data, 0x1000).unwrap();
        
        assert_eq!(insn.mnemonic, Mnemonic::Nop);
        assert_eq!(insn.metadata.length, 1);
    }

    #[test]
    fn test_decode_ret() {
        let decoder = Decoder::new(Architecture::X64);
        let data = vec![0xC3];
        let insn = decoder.decode(&data, 0x1000).unwrap();
        
        assert_eq!(insn.mnemonic, Mnemonic::Ret);
        assert_eq!(insn.metadata.length, 1);
    }

    #[test]
    fn test_decode_call() {
        let decoder = Decoder::new(Architecture::X64);
        let data = vec![0xE8, 0x00, 0x00, 0x00, 0x00];
        let insn = decoder.decode(&data, 0x1000).unwrap();
        
        assert_eq!(insn.mnemonic, Mnemonic::Call);
        assert_eq!(insn.metadata.length, 5);
    }

    #[test]
    fn test_decode_jmp() {
        let decoder = Decoder::new(Architecture::X64);
        let data = vec![0xE9, 0x00, 0x00, 0x00, 0x00];
        let insn = decoder.decode(&data, 0x1000).unwrap();
        
        assert_eq!(insn.mnemonic, Mnemonic::Jmp);
        assert_eq!(insn.metadata.length, 5);
    }

    #[test]
    fn test_decode_mov_reg_imm() {
        let decoder = Decoder::new(Architecture::X64);
        let data = vec![0xB8, 0x34, 0x12, 0x00, 0x00];
        let insn = decoder.decode(&data, 0x1000).unwrap();
        
        assert_eq!(insn.mnemonic, Mnemonic::Mov);
        assert_eq!(insn.operands.len(), 2);
    }

    #[test]
    fn test_decode_push_r64() {
        let decoder = Decoder::new(Architecture::X64);
        let data = vec![0x50];
        let insn = decoder.decode(&data, 0x1000).unwrap();
        
        assert_eq!(insn.mnemonic, Mnemonic::Push);
        assert!(insn.metadata.attributes.is_stack_op);
    }

    #[test]
    fn test_decode_pop_r64() {
        let decoder = Decoder::new(Architecture::X64);
        let data = vec![0x58];
        let insn = decoder.decode(&data, 0x1000).unwrap();
        
        assert_eq!(insn.mnemonic, Mnemonic::Pop);
        assert!(insn.metadata.attributes.is_stack_op);
    }

    #[test]
    fn test_decode_int() {
        let decoder = Decoder::new(Architecture::X64);
        let data = vec![0xCD, 0x80];
        let insn = decoder.decode(&data, 0x1000).unwrap();
        
        assert_eq!(insn.mnemonic, Mnemonic::Int);
        assert_eq!(insn.metadata.length, 2);
    }
}

#[cfg(test)]
mod prefix_tests {
    use super::*;

    #[test]
    fn test_decode_with_rex_prefix() {
        let decoder = Decoder::new(Architecture::X64);
        let data = vec![0x48, 0x8B, 0x00]; // MOV RAX, [RAX]
        let insn = decoder.decode(&data, 0x1000).unwrap();
        
        assert_eq!(insn.mnemonic, Mnemonic::Mov);
    }

    #[test]
    fn test_decode_with_operand_size_override() {
        let decoder = Decoder::new(Architecture::X64);
        let data = vec![0x66, 0xB8, 0x34, 0x12]; // MOV AX, 0x1234
        let insn = decoder.decode(&data, 0x1000).unwrap();
        
        assert_eq!(insn.mnemonic, Mnemonic::Mov);
    }
}