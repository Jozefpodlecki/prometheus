use crate::isa::Register;

pub fn decode_register(reg: u8, ext1: bool, ext2: bool, is_64bit: bool, vector_len: u16) -> Register {
    let mut index = reg as u16 + if ext1 { 8 } else { 0 } + if ext2 { 16 } else { 0 };
    if index > 31 { index = 0; }
    
    if vector_len == 0xFFFF {
        return match index {
            0 => Register::K0, 1 => Register::K1, 2 => Register::K2, 3 => Register::K3,
            4 => Register::K4, 5 => Register::K5, 6 => Register::K6, 7 => Register::K7,
            _ => Register::K0,
        };
    }

    if vector_len == 0xFFFE {
        return match index {
            0 => Register::St0, 1 => Register::St1, 2 => Register::St2, 3 => Register::St3,
            4 => Register::St4, 5 => Register::St5, 6 => Register::St6, 7 => Register::St7,
            _ => Register::St0,
        };
    }

    if vector_len > 0 {
        return match vector_len {
            128 => decode_xmm(index),
            256 => decode_ymm(index),
            512 => decode_zmm(index),
            _ => Register::Xmm0,
        };
    }

    if is_64bit {
        decode_gpr64(index)
    } else {
        decode_gpr32(index)
    }
}

fn decode_xmm(index: u16) -> Register {
    match index {
        0 => Register::Xmm0, 1 => Register::Xmm1, 2 => Register::Xmm2, 3 => Register::Xmm3,
        4 => Register::Xmm4, 5 => Register::Xmm5, 6 => Register::Xmm6, 7 => Register::Xmm7,
        8 => Register::Xmm8, 9 => Register::Xmm9, 10 => Register::Xmm10, 11 => Register::Xmm11,
        12 => Register::Xmm12, 13 => Register::Xmm13, 14 => Register::Xmm14, 15 => Register::Xmm15,
        16 => Register::Xmm16, 17 => Register::Xmm17, 18 => Register::Xmm18, 19 => Register::Xmm19,
        20 => Register::Xmm20, 21 => Register::Xmm21, 22 => Register::Xmm22, 23 => Register::Xmm23,
        24 => Register::Xmm24, 25 => Register::Xmm25, 26 => Register::Xmm26, 27 => Register::Xmm27,
        28 => Register::Xmm28, 29 => Register::Xmm29, 30 => Register::Xmm30, 31 => Register::Xmm31,
        _ => Register::Xmm0,
    }
}

fn decode_ymm(index: u16) -> Register {
    match index {
        0 => Register::Ymm0, 1 => Register::Ymm1, 2 => Register::Ymm2, 3 => Register::Ymm3,
        4 => Register::Ymm4, 5 => Register::Ymm5, 6 => Register::Ymm6, 7 => Register::Ymm7,
        8 => Register::Ymm8, 9 => Register::Ymm9, 10 => Register::Ymm10, 11 => Register::Ymm11,
        12 => Register::Ymm12, 13 => Register::Ymm13, 14 => Register::Ymm14, 15 => Register::Ymm15,
        16 => Register::Ymm16, 17 => Register::Ymm17, 18 => Register::Ymm18, 19 => Register::Ymm19,
        20 => Register::Ymm20, 21 => Register::Ymm21, 22 => Register::Ymm22, 23 => Register::Ymm23,
        24 => Register::Ymm24, 25 => Register::Ymm25, 26 => Register::Ymm26, 27 => Register::Ymm27,
        28 => Register::Ymm28, 29 => Register::Ymm29, 30 => Register::Ymm30, 31 => Register::Ymm31,
        _ => Register::Ymm0,
    }
}

fn decode_zmm(index: u16) -> Register {
    match index {
        0 => Register::Zmm0, 1 => Register::Zmm1, 2 => Register::Zmm2, 3 => Register::Zmm3,
        4 => Register::Zmm4, 5 => Register::Zmm5, 6 => Register::Zmm6, 7 => Register::Zmm7,
        8 => Register::Zmm8, 9 => Register::Zmm9, 10 => Register::Zmm10, 11 => Register::Zmm11,
        12 => Register::Zmm12, 13 => Register::Zmm13, 14 => Register::Zmm14, 15 => Register::Zmm15,
        16 => Register::Zmm16, 17 => Register::Zmm17, 18 => Register::Zmm18, 19 => Register::Zmm19,
        20 => Register::Zmm20, 21 => Register::Zmm21, 22 => Register::Zmm22, 23 => Register::Zmm23,
        24 => Register::Zmm24, 25 => Register::Zmm25, 26 => Register::Zmm26, 27 => Register::Zmm27,
        28 => Register::Zmm28, 29 => Register::Zmm29, 30 => Register::Zmm30, 31 => Register::Zmm31,
        _ => Register::Zmm0,
    }
}

fn decode_gpr64(index: u16) -> Register {
    match index {
        0 => Register::Rax, 1 => Register::Rcx, 2 => Register::Rdx, 3 => Register::Rbx,
        4 => Register::Rsp, 5 => Register::Rbp, 6 => Register::Rsi, 7 => Register::Rdi,
        8 => Register::R8, 9 => Register::R9, 10 => Register::R10, 11 => Register::R11,
        12 => Register::R12, 13 => Register::R13, 14 => Register::R14, 15 => Register::R15,
        16 => Register::R16, 17 => Register::R17, 18 => Register::R18, 19 => Register::R19,
        20 => Register::R20, 21 => Register::R21, 22 => Register::R22, 23 => Register::R23,
        24 => Register::R24, 25 => Register::R25, 26 => Register::R26, 27 => Register::R27,
        28 => Register::R28, 29 => Register::R29, 30 => Register::R30, 31 => Register::R31,
        _ => Register::Rax,
    }
}

fn decode_gpr32(index: u16) -> Register {
    match index {
        0 => Register::Eax, 1 => Register::Ecx, 2 => Register::Edx, 3 => Register::Ebx,
        4 => Register::Esp, 5 => Register::Ebp, 6 => Register::Esi, 7 => Register::Edi,
        8 => Register::R8d, 9 => Register::R9d, 10 => Register::R10d, 11 => Register::R11d,
        12 => Register::R12d, 13 => Register::R13d, 14 => Register::R14d, 15 => Register::R15d,
        16 => Register::R16d, 17 => Register::R17d, 18 => Register::R18d, 19 => Register::R19d,
        20 => Register::R20d, 21 => Register::R21d, 22 => Register::R22d, 23 => Register::R23d,
        24 => Register::R24d, 25 => Register::R25d, 26 => Register::R26d, 27 => Register::R27d,
        28 => Register::R28d, 29 => Register::R29d, 30 => Register::R30d, 31 => Register::R31d,
        _ => Register::Eax,
    }
}