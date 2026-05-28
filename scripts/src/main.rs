mod cli;
mod generate_isa;
mod plot_benchmarks;

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tracing::*;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};
use std::str::FromStr;

use cli::{Cli, Commands};
use generate_isa::{CsvParser, CodeGenerator, Config as IsaConfig, Downloader};
use plot_benchmarks::{BenchmarkConfig, BenchmarkVisualizer};

use crate::generate_isa::DecoderTablesGenerator;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    setup_logging(cli.verbose)?;
    
    match cli.command {
        Commands::GenerateIsa { output, csv_url, local_csv } => {
            run_generate_isa(output, csv_url, local_csv).await?;
        }
        Commands::PlotBenchmarks { output, width, height, bar_width, benchmarks, engines } => {
            run_plot_benchmarks(output, width, height, bar_width, benchmarks, engines)?;
        }
        Commands::All { isa_output, chart_output, skip_existing_isa } => {
            run_all(isa_output, chart_output, skip_existing_isa).await?;
        }
    }
    
    Ok(())
}

fn setup_logging(verbose: bool) -> Result<()> {
    let filter = if verbose {
        EnvFilter::from_str("debug").unwrap()
    } else {
        EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::from_str("info").unwrap())
    };
    
    tracing_subscriber::registry()
        .with(fmt::layer().with_target(true).with_thread_ids(true))
        .with(filter)
        .init();
    
    Ok(())
}

async fn run_generate_isa(output: PathBuf, csv_url: Option<String>, local_csv: Option<PathBuf>) -> Result<()> {
    info!("Starting ISA generation");
    
    let mut config = IsaConfig::with_defaults()?
        .with_output_path(output);
    
    if let Some(url) = csv_url {
        config = config.with_csv_url(url);
    }
    
    let downloader = Downloader::new(&config)?;
    let parser = CsvParser::new();
    let generator = CodeGenerator::new();

    let csv_content = if let Some(local_path) = local_csv {
        info!("Reading local CSV file: {}", local_path.display());
        tokio::fs::read_to_string(local_path).await?
    } else {
        info!("Downloading opcode database from: {}", config.csv_url);
        downloader.download_csv().await?
    };
    
    info!("Parsing CSV data");
    let (mnemonics, opcode_maps) = parser.parse(&csv_content)?;
    
    info!("Generating mnemonic enum");
    let autogen_isa_output_path = config.output_path.join("autogen_isa.rs");
    generator.generate(&mnemonics, &opcode_maps, &autogen_isa_output_path).await?;
    info!("ISA generation completed: {}", autogen_isa_output_path.display()); 

    // info!("Generating decoder tables");
    // let decoder_tables_path = config.output_path.join("decoder_tables.rs");
    // DecoderTablesGenerator::generate(&csv_content, &decoder_tables_path).await?;
    
    // info!("Decoder tables completed: {}", decoder_tables_path.display()); 

    Ok(())
}

fn run_plot_benchmarks(
    output: PathBuf,
    width: u32,
    height: u32,
    bar_width: f64,
    benchmarks: Option<Vec<String>>,
    engines: Option<Vec<String>>,
) -> Result<()> {
    info!("Starting benchmark visualization");
    
    let mut config = BenchmarkConfig::new()
        .with_output_path(output)
        .with_dimensions(width, height)
        .with_bar_width(bar_width);
    
    if let Some(b) = benchmarks {
        config = config.with_benchmarks(b);
    }
    
    if let Some(e) = engines {
        config = config.with_engines(e);
    }
    
    let visualizer = BenchmarkVisualizer::new(config);
    visualizer.run()?;
    
    info!("Benchmark chart generated");
    
    Ok(())
}

async fn run_all(isa_output: PathBuf, chart_output: PathBuf, skip_existing_isa: bool) -> Result<()> {
    // Check if ISA file already exists
    if skip_existing_isa && isa_output.exists() {
        info!("Skipping ISA generation (file exists): {}", isa_output.display());
    } else {
        info!("Running ISA generation...");
        run_generate_isa(isa_output, None, None).await?;
    }
    
    info!("Running benchmark visualization...");
    run_plot_benchmarks(chart_output, 1200, 700, 0.2, None, None)?;
    
    info!("All tasks completed successfully");
    
    Ok(())
}