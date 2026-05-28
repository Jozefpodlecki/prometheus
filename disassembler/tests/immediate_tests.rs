use prometheus_disassembler::isa::*;
use prometheus_disassembler::Decoder;

#[cfg(test)]
mod immediate_tests {
    use super::*;

    #[test]
    fn test_decode_16bit_immediate() {
        let decoder = Decoder::new(Architecture::X64);
        let data = vec![0x66, 0xB8, 0x34, 0x12];
        let insn = decoder.decode(&data, 0x1000).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::Mov);
    }

    #[test]
    fn test_decode_32bit_immediate() {
        let decoder = Decoder::new(Architecture::X64);
        let data = vec![0xB8, 0x78, 0x56, 0x34, 0x12];
        let insn = decoder.decode(&data, 0x1000).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::Mov);
    }

    #[test]
    fn test_decode_64bit_immediate() {
        let decoder = Decoder::new(Architecture::X64);
        let data = vec![0x48, 0xB8, 0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01];
        let insn = decoder.decode(&data, 0x1000).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::Mov);
    }
}