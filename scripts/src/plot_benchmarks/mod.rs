pub mod config;
pub mod models;
pub mod collector;
pub mod chart;
pub mod types;

pub use config::BenchmarkConfig;
pub use collector::BenchmarkCollector;
pub use chart::ChartGenerator;

use anyhow::Result;

pub struct BenchmarkVisualizer {
    config: BenchmarkConfig,
}

impl BenchmarkVisualizer {
    pub fn new(config: BenchmarkConfig) -> Self {
        Self { config }
    }
    
    pub fn run(&self) -> Result<()> {
        let collect_path = "target/criterion";
        let collector = BenchmarkCollector::new(collect_path);
        let data = collector.collect(&self.config.benchmarks, &self.config.engines)?;
        
        let generator = ChartGenerator::new(self.config.clone());
        generator.generate(&data)?;
        
        Ok(())
    }
}