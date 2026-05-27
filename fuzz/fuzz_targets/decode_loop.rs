#![no_main]
use libfuzzer_sys::fuzz_target;
use prometheus_disassembler::{Decoder, Architecture};
use zydis::{Decoder as ZydisDecoder, MachineMode, StackWidth};

fuzz_target!(|data: &[u8]| {
    // We only care about ensuring that the engine NEVER panics or triggers an out-of-bounds read
    // on malformed data. If it returns an Error gracefully, that is correct behavior.
    let decoder = Decoder::new(Architecture::X64);
    let prom_res = decoder.decode(data, 0x1000);
    
    // Differential Testing: Compare length against Zydis
    let zy_dec = ZydisDecoder::new64();
    let zy_res = zy_dec.decode_first::<zydis::AllOperands>(data);
    
    if let Ok(prom_insn) = prom_res {
        // If Prometheus successfully decoded it, Zydis should also successfully decode it,
        // and their lengths should match. (There are rare undocumented edge cases where one might reject,
        // but length agreement is critical when both succeed).
        if let Ok(Some(zy_insn)) = zy_res {
            assert_eq!(
                prom_insn.metadata.length, 
                zy_insn.length,
                "Length mismatch between Prometheus ({}) and Zydis ({}) on bytes: {:02X?}",
                prom_insn.metadata.length,
                zy_insn.length,
                &data[..std::cmp::min(15, data.len())]
            );
        }
    }
});
