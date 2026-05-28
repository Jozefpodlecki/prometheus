use crate::decoder::session::DecodeSession;
use crate::decoder::register;
use crate::decoder::types::*;
use crate::error::Result;
use crate::isa::*;

pub fn decode_modrm_sib(
    session: &mut DecodeSession,
    rex: &Rex,
    rex2: &Rex2,
    vex: &Vex,
    evex: &Evex,
    eff_op_size: OperandSize,
    eff_addr_size: OperandSize,
    vector_len: u16,
    reg_is_dst: bool,
    segment_override: Option<Segment>,
    segments: &mut InstructionSegments,
    arch: Architecture,
) -> Result<(Operand, Operand)> {
    let modrm = session.read_u8()?;
    let mode = (modrm >> 6) & 0x03;
    let reg_field = (modrm >> 3) & 0x07;
    let rm_field = modrm & 0x07;

    let is_64bit = eff_op_size == OperandSize::Size64 || evex.w;
    let reg = register::decode_register(
        reg_field,
        rex.r || vex.r || evex.r || rex2.r,
        rex2.r_prime || evex.r_prime,
        is_64bit,
        vector_len,
    );

    let reg_op = Operand::Register {
        reg,
        access: if reg_is_dst {
            AccessType::Write
        } else {
            AccessType::Read
        },
        visibility: Visibility::Explicit,
        opmask: None,
        zeroing: false,
    };

    let rm_op = if mode == 3 {
        let rm_reg = register::decode_register(
            rm_field,
            rex.b || vex.b || evex.b || rex2.b,
            rex2.b_prime,
            is_64bit,
            vector_len,
        );
        Operand::Register {
            reg: rm_reg,
            access: if reg_is_dst {
                AccessType::Read
            } else {
                AccessType::Write
            },
            visibility: Visibility::Explicit,
            opmask: None,
            zeroing: false,
        }
    } else {
        decode_memory_operand(
            session,
            mode,
            rm_field,
            rex,
            rex2,
            vex,
            evex,
            eff_op_size,
            eff_addr_size,
            reg_is_dst,
            segment_override,
            segments,
            arch,
        )?
    };

    Ok((reg_op, rm_op))
}

fn decode_memory_operand(
    session: &mut DecodeSession,
    mode: u8,
    rm_field: u8,
    rex: &Rex,
    rex2: &Rex2,
    vex: &Vex,
    evex: &Evex,
    eff_op_size: OperandSize,
    eff_addr_size: OperandSize,
    reg_is_dst: bool,
    segment_override: Option<Segment>,
    segments: &mut InstructionSegments,
    arch: Architecture,
) -> Result<Operand> {
    let mut base: Option<Register> = None;
    let mut index: Option<Register> = None;
    let mut scale = 0u8;
    let mut disp = 0i64;

    if rm_field == 4 {
        segments.sib.offset = session.cursor as u8;
        segments.sib.length = 1;

        let sib = session.read_u8()?;
        scale = 1 << ((sib >> 6) & 0x03);
        let index_field = (sib >> 3) & 0x07;
        let base_field = sib & 0x07;

        let has_index_ext = rex.x || rex2.x || vex.x || evex.x;
        if index_field != 4 || has_index_ext {
            index = Some(register::decode_register(
                index_field,
                has_index_ext,
                rex2.x_prime,
                eff_addr_size == OperandSize::Size64,
                0,
            ));
        }

        if base_field == 5 && mode == 0 {
            disp = session.read_i32()? as i64;
        } else {
            let has_base_ext = rex.b || rex2.b || vex.b || evex.b;
            base = Some(register::decode_register(
                base_field,
                has_base_ext,
                rex2.b_prime,
                eff_addr_size == OperandSize::Size64,
                0,
            ));
        }
    } else if rm_field == 5 && mode == 0 {
        if arch == Architecture::X64 {
            base = Some(Register::Rip);
        }
        disp = session.read_i32()? as i64;
    } else {
        let has_base_ext = rex.b || rex2.b || vex.b || evex.b;
        base = Some(register::decode_register(
            rm_field,
            has_base_ext,
            rex2.b_prime,
            eff_addr_size == OperandSize::Size64,
            0,
        ));
    }

    let disp_start = session.cursor as u8;
    if mode == 1 {
        disp = session.read_i8()? as i64;
    } else if mode == 2 {
        disp = session.read_i32()? as i64;
    }

    if session.cursor as u8 > disp_start {
        segments.displacement.offset = disp_start;
        segments.displacement.length = (session.cursor as u8) - disp_start;
    }

    let size = match eff_op_size {
        OperandSize::Size8 => 8,
        OperandSize::Size16 => 16,
        OperandSize::Size32 => 32,
        OperandSize::Size64 => 64,
        _ => 32,
    };

    Ok(Operand::Memory {
        mem: MemoryAccess {
            segment: segment_override,
            base,
            index,
            scale,
            displacement: disp,
            size,
            broadcast: evex.present && evex.b_bit,
            absolute_address: None,
        },
        access: if reg_is_dst {
            AccessType::Read
        } else {
            AccessType::Write
        },
        visibility: Visibility::Explicit,
        opmask: None,
        zeroing: false,
    })
}