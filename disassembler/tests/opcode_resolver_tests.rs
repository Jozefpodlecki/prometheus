use prometheus_disassembler::decoder::opcode_resolver::resolve_opcode;
use prometheus_disassembler::decoder::session::DecodeSession;
use prometheus_disassembler::isa::*;

#[cfg(test)]
mod three_byte_tests {
    use super::*;

    #[test]
    fn test_aesenc() {
        let session = DecodeSession::new(&[]);
        let result = resolve_opcode(0xDC, false, true, &session).unwrap();
        assert_eq!(result.mnemonic, Mnemonic::Aesenc);
        assert_eq!(result.extension, IsaExtension::AES);
    }

    #[test]
    fn test_aesdec() {
        let session = DecodeSession::new(&[]);
        let result = resolve_opcode(0xDE, false, true, &session).unwrap();
        assert_eq!(result.mnemonic, Mnemonic::Aesdec);
        assert_eq!(result.extension, IsaExtension::AES);
    }

    #[test]
    fn test_endbr64() {
        let session = DecodeSession::new(&[]);
        let result = resolve_opcode(0xFA, false, true, &session).unwrap();
        assert_eq!(result.mnemonic, Mnemonic::Endbr64);
        assert_eq!(result.extension, IsaExtension::CET);
    }
}

#[cfg(test)]
mod two_byte_jump_tests {
    use super::*;

    #[test]
    fn test_jz() {
        let session = DecodeSession::new(&[]);
        let result = resolve_opcode(0x84, true, false, &session).unwrap();
        assert_eq!(result.mnemonic, Mnemonic::Jz);
        assert_eq!(result.control_flow, ControlFlow::ConditionalBranch);
    }

    #[test]
    fn test_jnz() {
        let session = DecodeSession::new(&[]);
        let result = resolve_opcode(0x85, true, false, &session).unwrap();
        assert_eq!(result.mnemonic, Mnemonic::Jnz);
        assert_eq!(result.control_flow, ControlFlow::ConditionalBranch);
    }

    #[test]
    fn test_jmp_range() {
        let jcc_opcodes = vec![
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
            0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
        ];
        
        for opcode in jcc_opcodes {
            let session = DecodeSession::new(&[]);
            let result = resolve_opcode(opcode, true, false, &session).unwrap();
            assert_eq!(result.control_flow, ControlFlow::ConditionalBranch);
            assert!(!result.has_modrm);
        }
}
}