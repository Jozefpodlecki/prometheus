use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct OpcodeMaps {
    pub single_byte: HashMap<u8, String>,
    pub prefixed_0f: HashMap<u8, String>,
}

#[derive(Debug, Clone)]
pub struct CsvRecord {
    pub mnemonic: String,
    pub encoding: String,
    pub opcode: Option<String>,
    pub operands: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Mnemonic(pub String);

impl Mnemonic {
    pub fn sanitized(&self) -> String {
        let mut s = self.0.to_lowercase();
        
        if let Some(first) = s.get_mut(0..1) {
            first.make_ascii_uppercase();
        }
        
        s.chars()
            .filter(|c| c.is_alphanumeric())
            .collect()
    }
    
    pub fn as_variant(&self) -> String {
        self.sanitized()
    }
}