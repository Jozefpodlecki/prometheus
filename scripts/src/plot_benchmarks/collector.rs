use anyhow::{Context, Result, bail};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

use crate::plot_benchmarks::models::ChartData;

pub struct BenchmarkCollector {
    criterion_dir: PathBuf,
}

impl BenchmarkCollector {
    pub fn new<P: AsRef<Path>>(criterion_dir: P) -> Self {
        Self { criterion_dir: criterion_dir.as_ref().into() }
    }
    
    pub fn collect(&self, benchmarks: &[String], engines: &[String]) -> Result<ChartData> {
        let mut values = Vec::new();
        let mut has_valid_data = false;
        
        for benchmark in benchmarks {
            let mut row = Vec::new();
            
            for engine in engines {
                let throughput = self.get_latest_throughput(benchmark, engine);
                row.push(throughput);
                
                if throughput > 0.0 {
                    info!("{} / {}: {:.2} MiB/s", benchmark, engine, throughput);
                    has_valid_data = true;
                } else {
                    warn!("{} / {}: No valid throughput data", benchmark, engine);
                }
            }
            
            values.push(row);
        }

        if !has_valid_data {
            bail!(
                "No valid benchmark data collected. \
                Make sure benchmark results exist in 'target/criterion/' and \
                the benchmark/engine names match the directory structure."
            );
        }
        
        Ok(ChartData {
            benchmarks: benchmarks.to_owned(),
            engines: engines.to_owned(),
            values,
        })
    }
    
    fn get_latest_throughput(&self, benchmark_name: &str, engine: &str) -> f64 {
        if !self.criterion_dir.exists() {
            warn!("Criterion directory not found: {}", self.criterion_dir.display());
            return 0.0;
        }
        
        let estimates_path = self.criterion_dir
            .join(benchmark_name)
            .join(engine)
            .join("new")
            .join("estimates.json");
        
        let benchmark_path = self.criterion_dir
            .join(benchmark_name)
            .join(engine)
            .join("new")
            .join("benchmark.json");
        
        if !estimates_path.exists() {
            warn!("Estimates file not found: {}", estimates_path.display());
            return 0.0;
        }
        
        let mean_time_ns = match self.read_mean_time(&estimates_path) {
            Ok(time) => time,
            Err(e) => {
                warn!("Failed to read mean time: {}", e);
                return 0.0;
            }
        };
        
        let throughput_bytes = self.read_throughput_bytes(&benchmark_path);
        
        if throughput_bytes > 0.0 && mean_time_ns > 0.0 {
            let mb_per_s = (throughput_bytes / (mean_time_ns / 1e9)) / (1024.0 * 1024.0);
            
            if mb_per_s > 1000.0 {
                warn!("Suspiciously high throughput: {:.2} MiB/s", mb_per_s);
                return 0.0;
            }
            
            return mb_per_s;
        }
        
        0.0
    }
    
    fn read_mean_time(&self, path: &Path) -> Result<f64> {
        let data = fs::read_to_string(path)
            .with_context(|| format!("Failed to read: {}", path.display()))?;
        
        let json: Value = serde_json::from_str(&data)
            .with_context(|| format!("Invalid JSON in: {}", path.display()))?;
        
        let mean_time = json["mean"]["point_estimate"]
            .as_f64()
            .context("Missing or invalid 'mean.point_estimate' field")?;
        
        Ok(mean_time)
    }
    
    fn read_throughput_bytes(&self, path: &Path) -> f64 {
        if !path.exists() {
            return 0.0;
        }
        
        let data = match fs::read_to_string(path) {
            Ok(d) => d,
            Err(e) => {
                warn!("Failed to read benchmark.json: {}", e);
                return 0.0;
            }
        };
        
        let json: Value = match serde_json::from_str(&data) {
            Ok(j) => j,
            Err(e) => {
                warn!("Invalid benchmark.json: {}", e);
                return 0.0;
            }
        };
        
        json["throughput"]["Bytes"]
            .as_f64()
            .unwrap_or(0.0)
    }
}