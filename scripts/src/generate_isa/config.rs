use anyhow::Result;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Config {
    pub csv_url: String,
    pub project_root: PathBuf,
    pub output_path: PathBuf,
    pub user_agent: String,
    pub request_timeout_secs: u64,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Self::with_defaults()
    }
    
    pub fn with_defaults() -> Result<Self> {
        let project_root = Self::find_project_root()?;

        Ok(Self {
            project_root: project_root.clone(),
            csv_url: "https://raw.githubusercontent.com/golang/arch/master/x86/x86.csv".to_string(),
            output_path: project_root,
            user_agent: format!("isa-generator/{}", env!("CARGO_PKG_VERSION")),
            request_timeout_secs: 30,
        })
    }
    
    pub fn with_output_path(mut self, path: PathBuf) -> Self {
        self.output_path = path;
        self
    }
    
    pub fn with_csv_url(mut self, url: String) -> Self {
        self.csv_url = url;
        self
    }
    
    fn find_project_root() -> Result<PathBuf> {
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
            .map_err(|_| anyhow::anyhow!("CARGO_MANIFEST_DIR not set"))?;
        
        let mut path = PathBuf::from(manifest_dir);
        
        while !path.join("Cargo.toml").exists() {
            if !path.pop() {
                anyhow::bail!("Could not find project root");
            }
        }
        
        Ok(path)
    }
}