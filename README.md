# Prometheus: High-Assurance x86-64 Disassembly

**Prometheus** is a memory-safe, deterministic, and zero-allocation disassembly engine written in safe Rust. It is built specifically for modern static analysis, symbolic execution, and dynamic instrumentation frameworks.

## Performance Benchmarks

Prometheus utilizes a simple, zero-allocation dispatch state machine. A benchmark suite is provided utilizing `criterion`. The current benchmark compares the decode throughput of `Prometheus`, `Zydis`, and `Capstone` across a highly volatile ~100KB buffer filled with EVEX payloads, REX/VEX combinations, and relative jumps.

```bash
cargo bench
```

*(See `benchmark_results.png` for a visual chart across Mixed, Legacy, and AVX-512 workloads).*

**Results (May 2026, Intel(R) Core(TM) i5-14600KF)**:
- **Prometheus**: ~37.8 MiB/s throughput
- **Zydis**: ~17.2 MiB/s throughput
- **Capstone**: ~12.6 MiB/s throughput *(Note: Capstone fails to natively process pure AVX-512 blocks without custom configuration, dropping out of that specific benchmark).*

*Note: These benchmarks measure real-world decoding into high-level AST structures which is how reversing tools actually use them. Prometheus reliably processes dense x86-64 instruction streams at over **2x the speed of Zydis** by eliminating formatter and semantic-compatibility overhead inside the hot loop.*

# Differential Fuzzing Against Zydis

Prometheus is continuously fuzzed against upstream engines like Zydis to ensure total structural adherence to the x86-64 manual, as well as 100% crash resilience on malformed inputs. The fuzzing harness feeds randomized byte streams to both engines and ensures the decoded instruction length exactly matches—if Zydis parses 4 bytes, Prometheus must parse exactly 4 bytes.

Run the fuzzer locally requiring nightly rust:
```bash
cargo install cargo-fuzz
cargo +nightly fuzz run decode_loop
```

## Features

- **Data-Driven Architecture**: Opcodes and flag semantics are automatically synthesized from upstream databases (e.g., Go Arch `x86.csv`) guaranteeing manual-mapping errors are eliminated.
- **Exhaustive Semantic Modeling**: Granular tracking for CPU status flags (Tested, Modified, Set, Cleared, Undefined) and explicit AST injection of implicit hardware operands.
- **Zero-Allocation**: Decodes directly from byte slices without touching the heap (`no_std` compatible by design).
- **Modern ISA Support**: Natively decodes Intel APX (REX2), AVX-512 (EVEX) masking/zeroing/broadcast attributes, AMD XOP, and Intel CET (`endbr64`).
- **Memory Safe**: Utilizes Rust's strict algebraic data types and bounds checking. The core parsing loop contains **zero** `unsafe` blocks.
- **C ABI & Bindings**: Ships with a stable C FFI and native bindings for Python, LuaJIT, Nim, and C/C++.

## Usage

Add Prometheus to your `Cargo.toml`:
```toml
[dependencies]
prometheus-disassembler = "0.1.0"
```

### Basic Example

```rust
use prometheus::{Decoder, Architecture};

fn main() {
    let decoder = Decoder::new(Architecture::X64);
    
    // MOV RAX, [RIP + 0x10]
    let bytes = [0x48, 0x8B, 0x05, 0x10, 0x00, 0x00, 0x00];
    
    let instruction = decoder.decode(&bytes, 0x1000).unwrap();
    println!("Mnemonic: {:?}", instruction.mnemonic);
    println!("Length: {} bytes", instruction.metadata.length);
}
```

## Language Bindings

Prometheus is designed to be the backbone of your reverse-engineering pipeline regardless of your host language. Inside the `bindings/` directory, you will find ready-to-use wrappers for:
- Python (`ctypes`)
- LuaJIT (`ffi`)
- Nim
- C/C++ Header (`prometheus.h`)

## License
To the extent possible under law, the author has waived all copyright and related or neighboring rights to this work. This project is published from Romania under the CC0 1.0 Universal Public Domain Dedication.

Please refer to the `CODE_OF_CONDUCT.md` for operational directives regarding this repository.
