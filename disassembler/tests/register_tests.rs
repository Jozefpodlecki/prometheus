#[cfg(test)]
mod tests {
    use prometheus_disassembler::decoder::register::decode_register;
    use prometheus_disassembler::isa::Register;

    #[test]
    fn test_decode_gpr64() {
        let reg = decode_register(0, false, false, true, 0);
        assert_eq!(reg, Register::Rax);
        
        let reg = decode_register(1, false, false, true, 0);
        assert_eq!(reg, Register::Rcx);
    }

    #[test]
    fn test_decode_with_extension() {
        let reg = decode_register(0, true, false, true, 0);
        assert_eq!(reg, Register::R8);
    }
}