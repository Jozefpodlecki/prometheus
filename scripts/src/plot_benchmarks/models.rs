#[derive(Debug, Clone)]
pub struct BenchmarkResult {
    pub name: String,
    pub engine: String,
    pub throughput_mb_s: f64,
}

#[derive(Debug, Clone)]
pub struct ThroughputData {
    pub benchmark: String,
    pub engine: String,
    pub value: f64,
}

#[derive(Debug, Clone)]
pub struct ChartData {
    pub benchmarks: Vec<String>,
    pub engines: Vec<String>,
    pub values: Vec<Vec<f64>>,
}

impl ChartData {
    pub fn max_value(&self) -> f64 {
        self.values
            .iter()
            .flat_map(|row| row.iter())
            .copied()
            .fold(0.0f64, f64::max)
            .max(10.0)
    }
    
    pub fn get_value(&self, bench_idx: usize, engine_idx: usize) -> f64 {
        self.values
            .get(bench_idx)
            .and_then(|row| row.get(engine_idx))
            .copied()
            .unwrap_or(0.0)
    }
}