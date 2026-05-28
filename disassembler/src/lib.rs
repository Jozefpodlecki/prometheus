/*
** Prometheus: A deterministic and secure-by-design disassembly engine.
**
** This engine is built with safety as the primary objective, ensuring memory 
** safety and architecture accuracy. It treats all input as untrusted and 
** performs rigorous bounds checking and validation at every stage of the 
** decoding pipeline.
**
** This work is dedicated to the public domain under CC0 1.0 Universal.
*/

pub mod error;
pub mod isa;
pub mod decoder;
pub mod validator;
pub mod formatter;
pub mod iter;
pub mod autogen_isa;
pub mod ffi;

pub use error::{DecoderError, Result};
pub use decoder::Decoder;
pub use isa::{Instruction, Architecture};
pub use validator::Validator;
pub use formatter::Formatter;
pub use iter::InstructionIterator;