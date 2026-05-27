use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use std::hint::black_box;
use prometheus_disassembler::{Decoder, Architecture};
use capstone::prelude::*;
use zydis::{Decoder as ZydisDecoder, MachineMode, StackWidth, AllOperands};

pub fn bench_mixed_workload(c: &mut Criterion) {
    let instruction_mix: Vec<u8> = vec![
        0x48, 0x8B, 0x05, 0x10, 0x00, 0x00, 0x00, // mov rax, [rip+0x10]
        0x48, 0x01, 0xC3,                         // add rbx, rax
        0x0F, 0x85, 0x44, 0x33, 0x22, 0x11,       // jnz rel32
        0x62, 0xF1, 0x6C, 0x49, 0x58, 0xCB,       // vaddps zmm1, zmm2, zmm3
        0xC5, 0xF8, 0x58, 0xCB,                   // vaddps xmm1, xmm2, xmm3
        0x90,                                     // nop
        0x0F, 0x05,                               // syscall
        0x48, 0x89, 0xD8,                         // mov rax, rbx
        0xC3,                                     // ret
    ];

    let mut code = Vec::with_capacity(100_000);
    for _ in 0..3000 {
        code.extend_from_slice(&instruction_mix);
    }

    let prom_dec = Decoder::new(Architecture::X64);
    let mut cs = Capstone::new().x86().mode(arch::x86::ArchMode::Mode64).build().unwrap();
    let zy_dec = ZydisDecoder::new64();

    let mut group = c.benchmark_group("Mixed_Workload");
    group.throughput(Throughput::Bytes(code.len() as u64));

    group.bench_function("Prometheus", |b| {
        b.iter(|| {
            let mut offset = 0;
            while offset < code.len() {
                if let Ok(insn) = prom_dec.decode(&code[offset..], 0x1000 + offset as u64) {
                    offset += insn.metadata.length as usize;
                    black_box(insn);
                } else {
                    offset += 1;
                }
            }
        })
    });

    group.bench_function("Zydis", |b| {
        b.iter(|| {
            let mut offset = 0;
            while offset < code.len() {
                if let Ok(Some(insn)) = zy_dec.decode_first::<AllOperands>(&code[offset..]) {
                    offset += insn.length as usize;
                    black_box(insn);
                } else {
                    offset += 1;
                }
            }
        })
    });

    group.bench_function("Capstone", |b| {
        b.iter(|| {
            if let Ok(insns) = cs.disasm_all(&code, 0x1000) {
                for i in insns.as_ref() {
                    black_box(i);
                }
            }
        })
    });
    group.finish();
}

pub fn bench_legacy_workload(c: &mut Criterion) {
    let instruction_mix: Vec<u8> = vec![
        0x50,                                     // push rax
        0x48, 0x89, 0xE5,                         // mov rbp, rsp
        0x48, 0x83, 0xEC, 0x10,                   // sub rsp, 16
        0x8B, 0x45, 0xFC,                         // mov eax, [rbp-4]
        0x03, 0x45, 0xF8,                         // add eax, [rbp-8]
        0x89, 0x45, 0xF4,                         // mov [rbp-12], eax
        0x48, 0x89, 0xEC,                         // mov rsp, rbp
        0x5D,                                     // pop rbp
        0xC3,                                     // ret
    ];

    let mut code = Vec::with_capacity(100_000);
    for _ in 0..4000 {
        code.extend_from_slice(&instruction_mix);
    }

    let prom_dec = Decoder::new(Architecture::X64);
    let mut cs = Capstone::new().x86().mode(arch::x86::ArchMode::Mode64).build().unwrap();
    let zy_dec = ZydisDecoder::new64();

    let mut group = c.benchmark_group("Legacy_Workload");
    group.throughput(Throughput::Bytes(code.len() as u64));

    group.bench_function("Prometheus", |b| {
        b.iter(|| {
            let mut offset = 0;
            while offset < code.len() {
                if let Ok(insn) = prom_dec.decode(&code[offset..], 0x1000 + offset as u64) {
                    offset += insn.metadata.length as usize;
                    black_box(insn);
                } else {
                    offset += 1;
                }
            }
        })
    });

    group.bench_function("Zydis", |b| {
        b.iter(|| {
            let mut offset = 0;
            while offset < code.len() {
                if let Ok(Some(insn)) = zy_dec.decode_first::<AllOperands>(&code[offset..]) {
                    offset += insn.length as usize;
                    black_box(insn);
                } else {
                    offset += 1;
                }
            }
        })
    });

    group.bench_function("Capstone", |b| {
        b.iter(|| {
            if let Ok(insns) = cs.disasm_all(&code, 0x1000) {
                for i in insns.as_ref() {
                    black_box(i);
                }
            }
        })
    });
    group.finish();
}

pub fn bench_avx512_workload(c: &mut Criterion) {
    let instruction_mix: Vec<u8> = vec![
        0x62, 0xF1, 0x6C, 0x49, 0x58, 0xCB,       // vaddps zmm1, zmm2, zmm3
        0x62, 0xF1, 0x6C, 0x49, 0x59, 0xCB,       // vmulps zmm1, zmm2, zmm3
        0x62, 0xF1, 0x6C, 0x49, 0x5C, 0xCB,       // vsubps zmm1, zmm2, zmm3
        0x62, 0xF1, 0x6C, 0x49, 0x5E, 0xCB,       // vdivps zmm1, zmm2, zmm3
        0x62, 0xF1, 0x6D, 0x49, 0x58, 0xCB,       // vaddpd zmm1, zmm2, zmm3
        0x62, 0xF1, 0x6D, 0x49, 0x59, 0xCB,       // vmulpd zmm1, zmm2, zmm3
    ];

    let mut code = Vec::with_capacity(100_000);
    for _ in 0..3000 {
        code.extend_from_slice(&instruction_mix);
    }

    let prom_dec = Decoder::new(Architecture::X64);
    let mut cs = Capstone::new().x86().mode(arch::x86::ArchMode::Mode64).build().unwrap();
    let zy_dec = ZydisDecoder::new64();

    let mut group = c.benchmark_group("AVX512_Workload");
    group.throughput(Throughput::Bytes(code.len() as u64));

    group.bench_function("Prometheus", |b| {
        b.iter(|| {
            let mut offset = 0;
            while offset < code.len() {
                if let Ok(insn) = prom_dec.decode(&code[offset..], 0x1000 + offset as u64) {
                    offset += insn.metadata.length as usize;
                    black_box(insn);
                } else {
                    offset += 1;
                }
            }
        })
    });

    group.bench_function("Zydis", |b| {
        b.iter(|| {
            let mut offset = 0;
            while offset < code.len() {
                if let Ok(Some(insn)) = zy_dec.decode_first::<AllOperands>(&code[offset..]) {
                    offset += insn.length as usize;
                    black_box(insn);
                } else {
                    offset += 1;
                }
            }
        })
    });

    group.bench_function("Capstone", |b| {
        b.iter(|| {
            if let Ok(insns) = cs.disasm_all(&code, 0x1000) {
                for i in insns.as_ref() {
                    black_box(i);
                }
            }
        })
    });
    group.finish();
}

criterion_group!(benches, bench_mixed_workload, bench_legacy_workload, bench_avx512_workload);
criterion_main!(benches);
