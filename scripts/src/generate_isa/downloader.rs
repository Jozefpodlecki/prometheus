use anyhow::{Context, Result};
use reqwest::{Client, ClientBuilder};
use std::time::Duration;
use tracing::{debug, info};

use super::config::Config;

pub struct Downloader {
    client: Client,
    url: String,
}

impl Downloader {
    pub fn new(config: &Config) -> Result<Self> {
        let client = ClientBuilder::new()
            .user_agent(&config.user_agent)
            .timeout(Duration::from_secs(config.request_timeout_secs))
            .build()
            .context("Failed to create HTTP client")?;
        
        Ok(Self {
            client,
            url: config.csv_url.clone(),
        })
    }
    
    pub async fn download_csv(&self) -> Result<String> {
        debug!("Downloading CSV from: {}", self.url);
        
        let response = self.client
            .get(&self.url)
            .send()
            .await
            .context("Failed to send HTTP request")?;
        
        if !response.status().is_success() {
            anyhow::bail!("HTTP error: {}", response.status());
        }
        
        let content = response
            .text()
            .await
            .context("Failed to read response body")?;
        
        info!("Downloaded {} bytes", content.len());
        
        Ok(content)
    }
}