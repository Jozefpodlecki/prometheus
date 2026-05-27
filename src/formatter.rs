use crate::isa::{Instruction, Mnemonic, Operand, Register, Immediate, Visibility};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Syntax {
    Intel,
    ATT,
}

pub trait SymbolResolver {
    fn resolve_symbol(&self, address: u64) -> Option<String>;
}

pub type FormatterHook = fn(&Instruction, &mut String) -> bool;

/*
** Canonical Intel and AT&T style disassembly formatter.
** This work is dedicated to the public domain under CC0 1.0 Universal.
*/
pub struct Formatter<'a> {
    syntax: Syntax,
    symbol_resolver: Option<&'a dyn SymbolResolver>,
    pre_format_hook: Option<FormatterHook>,
    post_format_hook: Option<FormatterHook>,
}

impl<'a> Formatter<'a> {
    pub fn new(syntax: Syntax) -> Self {
        Self { syntax, symbol_resolver: None, pre_format_hook: None, post_format_hook: None }
    }

    pub fn with_symbol_resolver(mut self, resolver: &'a dyn SymbolResolver) -> Self {
        self.symbol_resolver = Some(resolver);
        self
    }
    
    pub fn with_pre_format_hook(mut self, hook: FormatterHook) -> Self {
        self.pre_format_hook = Some(hook);
        self
    }
    
    pub fn with_post_format_hook(mut self, hook: FormatterHook) -> Self {
        self.post_format_hook = Some(hook);
        self
    }

    pub fn format_intel(instruction: &Instruction) -> String {
        Self::new(Syntax::Intel).format(instruction)
    }

    pub fn format(&self, instruction: &Instruction) -> String {
        let mut out = String::new();
        
        if let Some(hook) = self.pre_format_hook {
            if hook(instruction, &mut out) {
                // If pre-hook returns true, it fully handled formatting
                return out;
            }
        }
        
        let mnemonic = self.format_mnemonic(instruction.mnemonic);
        let mut operands: Vec<String> = instruction.operands.iter()
            .filter(|op| match op {
                Operand::Register { visibility, .. } => *visibility == Visibility::Explicit,
                Operand::Immediate { visibility, .. } => *visibility == Visibility::Explicit,
                Operand::Memory { visibility, .. } => *visibility == Visibility::Explicit,
            })
            .map(|op| self.format_operand(op))
            .collect();

        if self.syntax == Syntax::ATT {
            operands.reverse();
        }

        if operands.is_empty() {
            out.push_str(&mnemonic);
        } else {
            out.push_str(&format!("{} {}", mnemonic, operands.join(", ")));
        }
        
        if let Some(hook) = self.post_format_hook {
            hook(instruction, &mut out);
        }
        
        out
    }

    fn format_mnemonic(&self, mnemonic: Mnemonic) -> String {
        match mnemonic {
            Mnemonic::Add => "add".to_string(),
            Mnemonic::Sub => "sub".to_string(),
            Mnemonic::Mov => "mov".to_string(),
            Mnemonic::Movs => "movs".to_string(),
            Mnemonic::Push => "push".to_string(),
            Mnemonic::Pop => "pop".to_string(),
            Mnemonic::Ret => "ret".to_string(),
            Mnemonic::Call => "call".to_string(),
            Mnemonic::Jmp => "jmp".to_string(),
            Mnemonic::Nop => "nop".to_string(),
            Mnemonic::Syscall => "syscall".to_string(),
            Mnemonic::Cmp => "cmp".to_string(),
            Mnemonic::Xor => "xor".to_string(),
            Mnemonic::And => "and".to_string(),
            Mnemonic::Or => "or".to_string(),
            Mnemonic::Adc => "adc".to_string(),
            Mnemonic::Sbb => "sbb".to_string(),
            Mnemonic::Jz => "jz".to_string(),
            Mnemonic::Jnz => "jnz".to_string(),
            Mnemonic::Js => "js".to_string(),
            Mnemonic::Jns => "jns".to_string(),
            Mnemonic::Jo => "jo".to_string(),
            Mnemonic::Jno => "jno".to_string(),
            Mnemonic::Jb => "jb".to_string(),
            Mnemonic::Jae => "jae".to_string(),
            Mnemonic::Lea => "lea".to_string(),
            Mnemonic::Int => "int".to_string(),
            Mnemonic::Vmovaps => "vmovaps".to_string(),
            Mnemonic::Vaddps => "vaddps".to_string(),
            Mnemonic::Vsubps => "vsubps".to_string(),
            Mnemonic::Test => "test".to_string(),
            Mnemonic::Inc => "inc".to_string(),
            Mnemonic::Dec => "dec".to_string(),
            Mnemonic::Pushfq => "pushfq".to_string(),
            Mnemonic::Popfq => "popfq".to_string(),
            Mnemonic::Clc => "clc".to_string(),
            Mnemonic::Stc => "stc".to_string(),
            Mnemonic::Cld => "cld".to_string(),
            Mnemonic::Std => "std".to_string(),
            Mnemonic::Aesenc => "aesenc".to_string(),
            Mnemonic::Aesdec => "aesdec".to_string(),
            Mnemonic::Vprotb => "vprotb".to_string(),
            Mnemonic::Ldtilecfg => "ldtilecfg".to_string(),
            Mnemonic::Sttilecfg => "sttilecfg".to_string(),
            Mnemonic::Tdpbf16ps => "tdpbf16ps".to_string(),
            Mnemonic::Fadd => "fadd".to_string(),
            Mnemonic::Fsub => "fsub".to_string(),
            Mnemonic::Fmul => "fmul".to_string(),
            Mnemonic::Fdiv => "fdiv".to_string(),
            Mnemonic::Endbr64 => "endbr64".to_string(),
            Mnemonic::Xadd => "xadd".to_string(),
            Mnemonic::Cmpxchg => "cmpxchg".to_string(),
            Mnemonic::Neg => "neg".to_string(),
            Mnemonic::Not => "not".to_string(),
            Mnemonic::Btc => "btc".to_string(),
            Mnemonic::Btr => "btr".to_string(),
            Mnemonic::Bts => "bts".to_string(),
            Mnemonic::Xchg => "xchg".to_string(),
            Mnemonic::Unknown => "??".to_string(),
            Mnemonic::Auto(auto) => auto.as_str().to_string(),
        }
    }

    fn format_operand(&self, operand: &Operand) -> String {
        match operand {
            Operand::Register { reg, visibility, opmask, zeroing, .. } => {
                if *visibility == Visibility::Hidden { return String::new(); }
                let mut s = self.format_register(*reg);
                if let Some(mask) = opmask {
                    s.push_str(&format!(" {{{}}}", self.format_register(*mask)));
                    if *zeroing {
                        s.push_str("{z}");
                    }
                }
                s
            },
            Operand::Immediate { imm, visibility } => {
                if *visibility == Visibility::Hidden { return String::new(); }
                let imm_str = self.format_immediate(*imm);
                if self.syntax == Syntax::ATT {
                    format!("${}", imm_str)
                } else {
                    imm_str
                }
            },
            Operand::Memory { mem, visibility, opmask, zeroing, .. } => {
                if *visibility == Visibility::Hidden { return String::new(); }
                
                let mut res = if self.syntax == Syntax::ATT {
                    let mut s = String::new();
                    if let Some(seg) = mem.segment {
                        s.push_str(&format!("%{}:", format!("{:?}", seg).to_lowercase()));
                    }
                    if mem.displacement != 0 {
                        if mem.displacement > 0 {
                            s.push_str(&format!("{:#x}", mem.displacement));
                        } else {
                            s.push_str(&format!("-{:#x}", -mem.displacement));
                        }
                    }
                    s.push_str("(");
                    if let Some(base) = mem.base {
                        s.push_str(&self.format_register(base));
                    }
                    if let Some(index) = mem.index {
                        s.push_str(&format!(",{}", self.format_register(index)));
                        if mem.scale > 1 {
                            s.push_str(&format!(",{}", mem.scale));
                        }
                    }
                    s.push_str(")");
                    
                    if mem.broadcast {
                        s.push_str("{1to16}");
                    }
                    s
                } else {
                    let mut s = String::new();
                    if let Some(seg) = mem.segment {
                        s.push_str(&format!("{}:", format!("{:?}", seg).to_lowercase()));
                    }
                    if let Some(base) = mem.base {
                        s.push_str(&self.format_register(base));
                    }
                    if let Some(index) = mem.index {
                        if !s.is_empty() && !s.ends_with(':') { s.push_str("+"); }
                        s.push_str(&self.format_register(index));
                        if mem.scale > 1 {
                            s.push_str(&format!("*{}", mem.scale));
                        }
                    }
                    if mem.displacement != 0 {
                        if !s.is_empty() && !s.ends_with(':') && mem.displacement > 0 {
                            s.push_str("+");
                        }
                        if mem.displacement > 0 {
                            s.push_str(&format!("{:#x}", mem.displacement));
                        } else {
                            s.push_str(&format!("-{:#x}", -mem.displacement));
                        }
                    }
                    let mut r = format!("[{}]", s);
                    if mem.broadcast {
                        r.push_str("{1to16}");
                    }
                    r
                };

                if let Some(mask) = opmask {
                    res.push_str(&format!(" {{{}}}", self.format_register(*mask)));
                    if *zeroing {
                        res.push_str("{z}");
                    }
                }
                res
            }
        }
    }

    fn format_register(&self, reg: Register) -> String {
        let name = format!("{:?}", reg).to_lowercase();
        if self.syntax == Syntax::ATT {
            format!("%{}", name)
        } else {
            name
        }
    }

    fn format_immediate(&self, imm: Immediate) -> String {
        // If we have a symbol resolver and it's a 64-bit imm (often an absolute address/branch target),
        // attempt to resolve it.
        if let Immediate::U64(val) = imm {
            if let Some(resolver) = self.symbol_resolver {
                if let Some(sym) = resolver.resolve_symbol(val) {
                    return format!("<{}>", sym);
                }
            }
        }
        
        match imm {
            Immediate::U8(v) => format!("{:#x}", v),
            Immediate::U16(v) => format!("{:#x}", v),
            Immediate::U32(v) => format!("{:#x}", v),
            Immediate::U64(v) => format!("{:#x}", v),
            Immediate::I8(v) => format!("{:#x}", v),
            Immediate::I16(v) => format!("{:#x}", v),
            Immediate::I32(v) => format!("{:#x}", v),
            Immediate::I64(v) => format!("{:#x}", v),
        }
    }
}
