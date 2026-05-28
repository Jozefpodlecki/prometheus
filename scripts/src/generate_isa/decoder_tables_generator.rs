// scripts/src/generate_isa/decoder_tables_generator.rs
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::Path;
use tokio::fs::File;
use tokio::io::{AsyncWriteExt, BufWriter};
use tracing::info;

use super::models::OpcodeMaps;
use super::parser::CsvParser;

pub struct DecoderTablesGenerator;

impl DecoderTablesGenerator {
    pub async fn generate(csv_content: &str, output_path: &Path) -> Result<()> {
        info!("Generating decoder tables from CSV");
        
        let parser = CsvParser::new();
        let (_, opcode_maps) = parser.parse(csv_content)?;
        
        let file = File::create(output_path)
            .await
            .with_context(|| format!("Failed to create file: {}", output_path.display()))?;
        
        let mut writer = BufWriter::new(file);
        
        Self::write_header(&mut writer).await?;
        Self::write_opcode_info_struct(&mut writer).await?;
        Self::write_one_byte_table(&mut writer, &opcode_maps.single_byte).await?;
        Self::write_two_byte_table(&mut writer, &opcode_maps.prefixed_0f).await?;
        Self::write_lookup_functions(&mut writer).await?;
        
        writer.flush().await?;
        
        info!("Decoder tables written to: {}", output_path.display());
        
        Ok(())
    }
    
    async fn write_header(writer: &mut BufWriter<File>) -> Result<()> {
        writer.write_all(b"// AUTO-GENERATED from x86.csv - DO NOT EDIT\n").await?;
        writer.write_all(b"// Provides O(1) lookup tables for opcode decoding\n\n").await?;
        writer.write_all(b"use crate::isa::Mnemonic;\n").await?;
        writer.write_all(b"use crate::autogen_isa::AutoMnemonic;\n\n").await?;
        Ok(())
    }
    
    async fn write_opcode_info_struct(writer: &mut BufWriter<File>) -> Result<()> {
        writer.write_all(b"#[derive(Debug, Clone, Copy, PartialEq, Eq)]\n").await?;
        writer.write_all(b"pub struct OpcodeInfo {\n").await?;
        writer.write_all(b"    pub mnemonic: Mnemonic,\n").await?;
        writer.write_all(b"    pub has_modrm: bool,\n").await?;
        writer.write_all(b"}\n\n").await?;
        
        writer.write_all(b"impl OpcodeInfo {\n").await?;
        writer.write_all(b"    #[inline]\n").await?;
        writer.write_all(b"    pub const fn from_auto(auto: AutoMnemonic, has_modrm: bool) -> Self {\n").await?;
        writer.write_all(b"        Self {\n").await?;
        writer.write_all(b"            mnemonic: Mnemonic::Auto(auto),\n").await?;
        writer.write_all(b"            has_modrm,\n").await?;
        writer.write_all(b"        }\n").await?;
        writer.write_all(b"    }\n").await?;
        writer.write_all(b"}\n\n").await?;
        
        Ok(())
    }
    
    async fn write_one_byte_table(
        writer: &mut BufWriter<File>,
        one_byte_map: &HashMap<u8, String>,
    ) -> Result<()> {
        writer.write_all(b"pub static ONE_BYTE_OPCODES: [Option<OpcodeInfo>; 256] = {\n").await?;
        writer.write_all(b"    let mut table = [None; 256];\n").await?;
        
        // Add entries from CSV
        for (&op, mnemonic) in one_byte_map {
            writer.write_all(
                format!("    table[0x{:02X}] = Some(OpcodeInfo::from_auto(AutoMnemonic::{}, true));\n", op, mnemonic).as_bytes()
            ).await?;
        }
        
        // Add manual overrides
        Self::write_manual_overrides(writer).await?;
        
        writer.write_all(b"    table\n").await?;
        writer.write_all(b"};\n\n").await?;
        
        Ok(())
    }
    
    async fn write_manual_overrides(writer: &mut BufWriter<File>) -> Result<()> {
        writer.write_all(b"    // Manual overrides (no ModR/M)\n").await?;
        
        let overrides: Vec<(u8, &str, bool)> = vec![
            (0x90, "Nop", false),
            (0x9C, "Pushfq", false),
            (0x9D, "Popfq", false),
            (0xC3, "Ret", false),
            (0xCC, "Int3", false),
            (0xCD, "Int", false),
            (0xCF, "Iret", false),
            (0xE8, "Call", false),
            (0xE9, "Jmp", false),
            (0xEB, "Jmp", false),
            (0xFA, "Cli", false),
            (0xFB, "Sti", false),
            (0xFC, "Cld", false),
            (0xFD, "Std", false),
        ];
        
        for (op, mnemonic, has_modrm) in overrides {
            writer.write_all(
                format!("    table[0x{:02X}] = Some(OpcodeInfo::from_auto(AutoMnemonic::{}, {}));\n", 
                    op, mnemonic, has_modrm
                ).as_bytes()
            ).await?;
        }
        
        Ok(())
    }
    
    async fn write_two_byte_table(
        writer: &mut BufWriter<File>,
        two_byte_map: &HashMap<u8, String>,
    ) -> Result<()> {
        writer.write_all(b"pub static TWO_BYTE_OPCODES: [Option<OpcodeInfo>; 256] = {\n").await?;
        writer.write_all(b"    let mut table = [None; 256];\n").await?;
        
        for (&op, mnemonic) in two_byte_map {
            writer.write_all(
                format!("    table[0x{:02X}] = Some(OpcodeInfo::from_auto(AutoMnemonic::{}, true));\n", op, mnemonic).as_bytes()
            ).await?;
        }
        
        // Add two-byte manual overrides
        writer.write_all(b"    // Manual overrides\n").await?;
        writer.write_all(b"    table[0x05] = Some(OpcodeInfo::from_auto(AutoMnemonic::Syscall, false));\n").await?;
        writer.write_all(b"    table[0x30] = Some(OpcodeInfo::from_auto(AutoMnemonic::Rdtsc, false));\n").await?;
        writer.write_all(b"    table[0x31] = Some(OpcodeInfo::from_auto(AutoMnemonic::Rdtscp, false));\n").await?;
        writer.write_all(b"    table[0x80] = Some(OpcodeInfo::from_auto(AutoMnemonic::Jmp, false));\n").await?;
        writer.write_all(b"    table[0x81] = Some(OpcodeInfo::from_auto(AutoMnemonic::Jmp, false));\n").await?;
        writer.write_all(b"    table[0x82] = Some(OpcodeInfo::from_auto(AutoMnemonic::Jmp, false));\n").await?;
        writer.write_all(b"    table[0x83] = Some(OpcodeInfo::from_auto(AutoMnemonic::Jmp, false));\n").await?;
        writer.write_all(b"    table[0x84] = Some(OpcodeInfo::from_auto(AutoMnemonic::Jz, false));\n").await?;
        writer.write_all(b"    table[0x85] = Some(OpcodeInfo::from_auto(AutoMnemonic::Jnz, false));\n").await?;
        
        writer.write_all(b"    table\n").await?;
        writer.write_all(b"};\n\n").await?;
        
        Ok(())
    }
    
    async fn write_lookup_functions(writer: &mut BufWriter<File>) -> Result<()> {
        writer.write_all(b"/// Fast O(1) lookup for single-byte opcodes\n").await?;
        writer.write_all(b"#[inline]\n").await?;
        writer.write_all(b"pub fn lookup_opcode(opcode: u8) -> Option<OpcodeInfo> {\n").await?;
        writer.write_all(b"    unsafe { ONE_BYTE_OPCODES.get_unchecked(opcode as usize).clone() }\n").await?;
        writer.write_all(b"}\n\n").await?;
        
        writer.write_all(b"/// Fast O(1) lookup for 2-byte opcodes (0F prefix)\n").await?;
        writer.write_all(b"#[inline]\n").await?;
        writer.write_all(b"pub fn lookup_opcode_0f(opcode: u8) -> Option<OpcodeInfo> {\n").await?;
        writer.write_all(b"    unsafe { TWO_BYTE_OPCODES.get_unchecked(opcode as usize).clone() }\n").await?;
        writer.write_all(b"}\n\n").await?;
        
        // Add helper for checking if opcode has ModR/M
        writer.write_all(b"/// Check if an opcode requires a ModR/M byte\n").await?;
        writer.write_all(b"#[inline]\n").await?;
        writer.write_all(b"pub fn has_modrm(opcode: u8, is_two_byte: bool) -> bool {\n").await?;
        writer.write_all(b"    if is_two_byte {\n").await?;
        writer.write_all(b"        lookup_opcode_0f(opcode).map_or(true, |info| info.has_modrm)\n").await?;
        writer.write_all(b"    } else {\n").await?;
        writer.write_all(b"        lookup_opcode(opcode).map_or(true, |info| info.has_modrm)\n").await?;
        writer.write_all(b"    }\n").await?;
        writer.write_all(b"}\n").await?;
        
        Ok(())
    }
}