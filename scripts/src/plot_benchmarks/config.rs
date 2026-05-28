use plotters::prelude::*;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct BenchmarkConfig {
    pub output_path: PathBuf,
    pub chart_width: u32,
    pub chart_height: u32,
    pub bar_width: f64,
    pub colors: Vec<RGBColor>,
    pub benchmarks: Vec<String>,
    pub engines: Vec<String>,
}

impl Default for BenchmarkConfig {
    fn default() -> Self {
        Self {
            output_path: PathBuf::from("benchmark_results.png"),
            chart_width: 1000,
            chart_height: 600,
            bar_width: 0.25,
            colors: vec![RED, BLUE, GREEN, MAGENTA, CYAN, YELLOW],
            benchmarks: vec![
                "Mixed_Workload".to_string(),
                "Legacy_Workload".to_string(),
                "AVX512_Workload".to_string(),
            ],
            engines: vec![
                "Prometheus".to_string(),
                "Zydis".to_string(),
                "Capstone".to_string(),
            ],
        }
    }
}

impl BenchmarkConfig {
    pub fn new() -> Self {
        Self::default()
    }
    
    pub fn with_output_path(mut self, path: PathBuf) -> Self {
        self.output_path = path;
        self
    }
    
    pub fn with_dimensions(mut self, width: u32, height: u32) -> Self {
        self.chart_width = width;
        self.chart_height = height;
        self
    }
    
    pub fn with_bar_width(mut self, bar_width: f64) -> Self {
        self.bar_width = bar_width;
        self
    }
    
    pub fn with_benchmarks(mut self, benchmarks: Vec<String>) -> Self {
        self.benchmarks = benchmarks;
        self
    }
    
    pub fn with_engines(mut self, engines: Vec<String>) -> Self {
        self.engines = engines;
        self
    }
}