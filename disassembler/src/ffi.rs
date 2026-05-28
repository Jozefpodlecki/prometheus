/*
** Prometheus FFI.
** This work is dedicated to the public domain under CC0 1.0 Universal.
*/

use core::slice;
use core::ffi::{c_char, c_void};
use core::ptr;
use std::ffi::CString;
use crate::isa::Architecture;
use crate::decoder::Decoder;
use crate::formatter::{Formatter, Syntax, SymbolResolver};

#[repr(C)]
pub enum PromArchitecture {
    PromArchX86 = 0,
    PromArchX64 = 1,
}

#[repr(C)]
pub enum PromSyntax {
    PromSyntaxIntel = 0,
    PromSyntaxATT = 1,
}

#[repr(C)]
pub struct PromInstruction {
    pub address: u64,
    pub length: u8,
    pub is_branch: bool,
    pub is_call: bool,
    pub is_vector: bool,
    pub branch_target: u64,
}

/* Opaque instance handle. */
pub struct PromDecoder(Decoder);

#[unsafe(no_mangle)]
pub extern "C" fn prom_decoder_create(arch: PromArchitecture) -> *mut PromDecoder {
    let rs_arch = match arch {
        PromArchitecture::PromArchX86 => Architecture::X86,
        PromArchitecture::PromArchX64 => Architecture::X64,
    };
    let decoder = Box::new(PromDecoder(Decoder::new(rs_arch)));
    Box::into_raw(decoder)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn prom_decoder_destroy(decoder: *mut PromDecoder) {
    if !decoder.is_null() {
        unsafe {
            let _ = Box::from_raw(decoder);
        }
    }
}

/* External symbol resolution hook. */
#[repr(C)]
pub struct PromSymbolResolver {
    context: *mut c_void,
    resolve: extern "C" fn(context: *mut c_void, address: u64, out_buffer: *mut c_char, max_len: usize) -> bool,
}

struct CSymbolResolverAdapter {
    c_resolver: PromSymbolResolver,
}

impl SymbolResolver for CSymbolResolverAdapter {
    fn resolve_symbol(&self, address: u64) -> Option<String> {
        let mut buffer = vec![0i8; 256];
        let success = (self.c_resolver.resolve)(self.c_resolver.context, address, buffer.as_mut_ptr() as *mut c_char, buffer.len());
        if success {
            unsafe {
                Some(core::ffi::CStr::from_ptr(buffer.as_ptr() as *const c_char).to_string_lossy().into_owned())
            }
        } else {
            None
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn prom_decode_and_format(
    decoder: *mut PromDecoder,
    buffer: *const u8,
    buffer_len: usize,
    address: u64,
    syntax: PromSyntax,
    resolver: *const PromSymbolResolver,
    out_string: *mut c_char,
    out_string_max_len: usize,
    out_instruction: *mut PromInstruction,
) -> bool {
    if decoder.is_null() || buffer.is_null() || out_string.is_null() || buffer_len == 0 {
        return false;
    }

    let dec = unsafe { &*decoder };
    let input = unsafe { slice::from_raw_parts(buffer, buffer_len) };

    match dec.0.decode(input, address) {
        Ok(instruction) => {
            if !out_instruction.is_null() {
                unsafe {
                    (*out_instruction).address = instruction.address;
                    (*out_instruction).length = instruction.metadata.length;
                    (*out_instruction).is_branch = instruction.metadata.control_flow == crate::isa::ControlFlow::ConditionalBranch || instruction.metadata.control_flow == crate::isa::ControlFlow::UnconditionalBranch;
                    (*out_instruction).is_call = instruction.metadata.control_flow == crate::isa::ControlFlow::Call;
                    (*out_instruction).is_vector = instruction.metadata.attributes.is_vector_op;
                    
                    let mut target = 0;
                    if (*out_instruction).is_branch || (*out_instruction).is_call {
                        for op in &instruction.operands {
                            if let crate::isa::Operand::Immediate { imm: crate::isa::Immediate::U64(v), .. } = op {
                                target = *v;
                            }
                        }
                    }
                    (*out_instruction).branch_target = target;
                }
            }

            let rs_syntax = match syntax {
                PromSyntax::PromSyntaxIntel => Syntax::Intel,
                PromSyntax::PromSyntaxATT => Syntax::ATT,
            };

            let mut fmt = Formatter::new(rs_syntax);
            
            /* Apply formatting adapter if hooked. */
            let mut adapter = None;
            if !resolver.is_null() {
                adapter = Some(CSymbolResolverAdapter {
                    c_resolver: unsafe { core::ptr::read(resolver) },
                });
            }
            
            if let Some(ref adapter_ref) = adapter {
                fmt = fmt.with_symbol_resolver(adapter_ref);
            }

            let formatted = fmt.format(&instruction);
            let c_str = match CString::new(formatted) {
                Ok(s) => s,
                Err(_) => return false,
            };

            let bytes = c_str.as_bytes_with_nul();
            if bytes.len() > out_string_max_len {
                return false;
            }

            unsafe {
                ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, out_string, bytes.len());
            }

            true
        }
        Err(_) => false,
    }
}