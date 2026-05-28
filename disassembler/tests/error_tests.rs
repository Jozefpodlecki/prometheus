use prometheus_disassembler::isa::*;
use prometheus_disassembler::Decoder;

#[cfg(test)]
mod error_tests {
    use super::*;

    #[test]
    fn test_truncated_instruction() {
        let decoder = Decoder::new(Architecture::X64);
        let data = vec![0xE8];
        let result = decoder.decode(&data, 0x1000);
        assert!(result.is_err());
    }

    #[test]
    fn test_truncated_instruction_two_byte() {
        let decoder = Decoder::new(Architecture::X64);
        let data = vec![0x0F];
        let result = decoder.decode(&data, 0x1000);
        assert!(result.is_err());
    }
}