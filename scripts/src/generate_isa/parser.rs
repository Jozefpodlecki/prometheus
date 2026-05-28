use anyhow::Result;
use csv::ReaderBuilder;
use std::collections::{BTreeSet, HashMap};
use std::io::Cursor;
use tracing::{debug, warn};

use super::models::{Mnemonic, OpcodeMaps};

pub struct CsvParser;

impl CsvParser {
    pub fn new() -> Self {
        Self
    }
    
    pub fn parse(&self, csv_data: &str) -> Result<(BTreeSet<Mnemonic>, OpcodeMaps)> {
        let mut mnemonics = BTreeSet::new();
        let mut single_byte_map = HashMap::new();
        let mut prefixed_0f_map = HashMap::new();

        let clean_csv: String = csv_data
            .lines()
            .filter(|line| !line.trim_start().starts_with('#'))
            .collect::<Vec<&str>>()
            .join("\n");
            
        let reader = ReaderBuilder::new()
            .has_headers(false)
            .from_reader(Cursor::new(clean_csv));
        
        for (idx, result) in reader.into_records().enumerate() {
            let record = match result {
                Ok(r) => r,
                Err(e) => {
                    warn!("Failed to parse CSV record {}: {}", idx, e);
                    continue;
                }
            };
            
            if record.is_empty() {
                continue;
            }
            
            let name = record.get(0).unwrap_or_default().trim();
            
            if name.starts_with('#') || name.is_empty() {
                continue;
            }
            
            let encoding = record.get(1).unwrap_or_default().trim();
            let mnemonic = Mnemonic(name.to_string());
            let sanitized = mnemonic.sanitized();
            
            if !sanitized.is_empty() {
                mnemonics.insert(mnemonic);
            }
            
            self.process_encoding(&encoding, &sanitized, &mut single_byte_map, &mut prefixed_0f_map);
        }
        
        Ok((mnemonics, OpcodeMaps {
            single_byte: single_byte_map,
            prefixed_0f: prefixed_0f_map,
        }))
    }
    
    fn process_encoding(
        &self,
        encoding: &str,
        mnemonic: &str,
        single_byte_map: &mut HashMap<u8, String>,
        prefixed_0f_map: &mut HashMap<u8, String>,
    ) {
        let parts: Vec<&str> = encoding.split_whitespace().collect();
        
        let clean_parts: Vec<&str> = parts
            .into_iter()
            .filter(|p| {
                !p.starts_with("REX")
                    && !p.starts_with("VEX")
                    && !p.starts_with("EVEX")
            })
            .collect();
        
        if clean_parts.len() >= 2 && clean_parts[0] == "0F" {
            if let Some(hex_byte) = clean_parts.get(1) {
                if self.is_hex_byte(hex_byte) {
                    if let Ok(op) = u8::from_str_radix(hex_byte, 16) {
                        prefixed_0f_map.entry(op).or_insert_with(|| mnemonic.to_string());
                        debug!("Mapped 0F {:02X} -> {}", op, mnemonic);
                    }
                }
            }
        } else if let Some(first) = clean_parts.first() {
            if self.is_hex_byte(first) {
                if let Ok(op) = u8::from_str_radix(first, 16) {
                    single_byte_map.entry(op).or_insert_with(|| mnemonic.to_string());
                    debug!("Mapped {:02X} -> {}", op, mnemonic);
                }
            }
        }
    }
    
    fn is_hex_byte(&self, s: &str) -> bool {
        s.len() == 2 && s.chars().all(|c| c.is_ascii_hexdigit())
    }
}