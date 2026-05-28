use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "disassembler-tools")]
#[command(author = "Your Name")]
#[command(version = "1.0")]
#[command(about = "Disassembler tools for ISA generation and benchmarking", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
    
    /// Enable verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Generate ISA from CSV database
    GenerateIsa {
        /// Output path for the generated Rust file
        #[arg(short, long, default_value = "disassembler/src")]
        output: PathBuf,
        
        /// CSV URL to download (optional, uses default if not specified)
        #[arg(short, long)]
        csv_url: Option<String>,
        
        /// Skip downloading and use local file
        #[arg(short, long)]
        local_csv: Option<PathBuf>,
    },
    
    /// Plot benchmark results
    PlotBenchmarks {
        /// Output path for the chart image
        #[arg(short, long, default_value = "benchmark_results.png")]
        output: PathBuf,
        
        /// Chart width in pixels
        #[arg(long, default_value = "1200")]
        width: u32,
        
        /// Chart height in pixels
        #[arg(long, default_value = "700")]
        height: u32,
        
        /// Bar width multiplier
        #[arg(long, default_value = "0.2")]
        bar_width: f64,
        
        /// Benchmarks to plot (overrides default)
        #[arg(short, long, value_delimiter = ',')]
        benchmarks: Option<Vec<String>>,
        
        /// Engines to compare (overrides default)
        #[arg(short, long, value_delimiter = ',')]
        engines: Option<Vec<String>>,
    },
    
    /// Run both ISA generation and benchmark plotting
    All {
        /// Output path for the generated Rust file
        #[arg(short, long, default_value = "../src/autogen_isa.rs")]
        isa_output: PathBuf,
        
        /// Output path for the chart image
        #[arg(short, long, default_value = "benchmark_results.png")]
        chart_output: PathBuf,
        
        /// Skip ISA generation if file exists
        #[arg(long)]
        skip_existing_isa: bool,
    },
}