//! Resource seeding for pre-downloading wordlists, tools, and dependencies
//!
//! Provides a "Seed Resources" feature that downloads all necessary resources
//! before they're needed during pentest operations.

use crate::error::{Error, Result};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::fs;
use tokio::io::AsyncWriteExt;

/// Resource types that can be seeded
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResourceType {
    Wordlist,
    Payload,
    Fuzzing,
    Network,
    Signature,
    ExploitDb,
    Binary,
    Documentation,
}

/// Seed tier for organizing resources
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SeedTier {
    /// Basic resources (wordlists, common payloads) ~150MB
    Basic,
    /// Enhanced resources (nuclei, exploitdb index, geoip) ~500MB
    Enhanced,
    /// Advanced resources (binaries, full databases, containers) ~2GB+
    Advanced,
}

/// A seedable resource
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedResource {
    pub name: String,
    pub resource_type: ResourceType,
    pub tier: SeedTier,
    pub url: String,
    pub size_mb: u64,
    pub description: String,
    pub destination: PathBuf,
    pub required: bool,
}

/// Progress callback for seeding operations
pub type ProgressCallback = Box<dyn Fn(SeedProgress) + Send + Sync>;

/// Progress information during seeding
#[derive(Debug, Clone)]
pub struct SeedProgress {
    pub resource_name: String,
    pub downloaded_mb: f64,
    pub total_mb: f64,
    pub percent: u8,
    pub status: SeedStatus,
}

/// Status of a seed operation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedStatus {
    Pending,
    Downloading,
    Extracting,
    Verifying,
    Complete,
    Failed,
    Skipped,
}

/// Seed manager for downloading and managing resources
pub struct SeedManager {
    resources: Vec<SeedResource>,
    base_dir: PathBuf,
}

impl SeedManager {
    /// Create a new seed manager
    pub fn new() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        let base_dir = PathBuf::from(home).join(".pick").join("resources");

        Self {
            resources: Self::default_resources(&base_dir),
            base_dir,
        }
    }

    /// Get default seedable resources
    fn default_resources(base_dir: &PathBuf) -> Vec<SeedResource> {
        let mut resources = Vec::new();

        // BASIC TIER (~150MB)
        resources.extend(vec![
            // Wordlists
            SeedResource {
                name: "RockYou Wordlist".to_string(),
                resource_type: ResourceType::Wordlist,
                tier: SeedTier::Basic,
                url: "https://download.weakpass.com/wordlists/90/rockyou.txt".to_string(),
                size_mb: 134,
                description: "14M passwords from RockYou breach".to_string(),
                destination: base_dir.join("wordlists/passwords/rockyou.txt"),
                required: true,
            },
            SeedResource {
                name: "Common Passwords".to_string(),
                resource_type: ResourceType::Wordlist,
                tier: SeedTier::Basic,
                url: "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt".to_string(),
                size_mb: 1,
                description: "Top 10k most common passwords".to_string(),
                destination: base_dir.join("wordlists/passwords/common-10k.txt"),
                required: true,
            },
            SeedResource {
                name: "Usernames".to_string(),
                resource_type: ResourceType::Wordlist,
                tier: SeedTier::Basic,
                url: "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt".to_string(),
                size_mb: 1,
                description: "Common usernames for brute force".to_string(),
                destination: base_dir.join("wordlists/usernames/common.txt"),
                required: false,
            },
            SeedResource {
                name: "Web Directories".to_string(),
                resource_type: ResourceType::Wordlist,
                tier: SeedTier::Basic,
                url: "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt".to_string(),
                size_mb: 1,
                description: "Common web directories for scanning".to_string(),
                destination: base_dir.join("wordlists/web/directories.txt"),
                required: false,
            },
            // Payloads
            SeedResource {
                name: "Reverse Shells".to_string(),
                resource_type: ResourceType::Payload,
                tier: SeedTier::Basic,
                url: "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md".to_string(),
                size_mb: 1,
                description: "Common reverse shell payloads (bash, python, php, etc)".to_string(),
                destination: base_dir.join("payloads/shells/reverse-shells.md"),
                required: false,
            },
            // Fuzzing
            SeedResource {
                name: "XSS Payloads".to_string(),
                resource_type: ResourceType::Fuzzing,
                tier: SeedTier::Basic,
                url: "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/XSS-BruteLogic.txt".to_string(),
                size_mb: 1,
                description: "XSS payloads for testing".to_string(),
                destination: base_dir.join("fuzzing/xss-payloads.txt"),
                required: false,
            },
            SeedResource {
                name: "SQL Injection Payloads".to_string(),
                resource_type: ResourceType::Fuzzing,
                tier: SeedTier::Basic,
                url: "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/SQLi/Generic-SQLi.txt".to_string(),
                size_mb: 1,
                description: "SQL injection payloads for testing".to_string(),
                destination: base_dir.join("fuzzing/sqli-payloads.txt"),
                required: false,
            },
            // Network
            SeedResource {
                name: "MAC Vendor Lookup (OUI)".to_string(),
                resource_type: ResourceType::Network,
                tier: SeedTier::Basic,
                url: "https://standards-oui.ieee.org/oui/oui.txt".to_string(),
                size_mb: 5,
                description: "MAC address vendor lookup database".to_string(),
                destination: base_dir.join("network/oui.txt"),
                required: false,
            },
        ]);

        // ENHANCED TIER (~500MB)
        resources.extend(vec![
            SeedResource {
                name: "Nuclei Templates".to_string(),
                resource_type: ResourceType::Signature,
                tier: SeedTier::Enhanced,
                url: "https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.zip".to_string(),
                size_mb: 50,
                description: "Nuclei vulnerability detection templates".to_string(),
                destination: base_dir.join("signatures/nuclei-templates.zip"),
                required: false,
            },
            SeedResource {
                name: "ExploitDB Index".to_string(),
                resource_type: ResourceType::ExploitDb,
                tier: SeedTier::Enhanced,
                url: "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv".to_string(),
                size_mb: 5,
                description: "ExploitDB searchable index (metadata only)".to_string(),
                destination: base_dir.join("exploits/exploitdb-index.csv"),
                required: false,
            },
            SeedResource {
                name: "GeoIP Database".to_string(),
                resource_type: ResourceType::Network,
                tier: SeedTier::Enhanced,
                url: "https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-City.mmdb".to_string(),
                size_mb: 100,
                description: "IP geolocation database".to_string(),
                destination: base_dir.join("network/geoip.mmdb"),
                required: false,
            },
            SeedResource {
                name: "Subdomains Wordlist".to_string(),
                resource_type: ResourceType::Wordlist,
                tier: SeedTier::Enhanced,
                url: "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt".to_string(),
                size_mb: 10,
                description: "Top 110k subdomains for enumeration".to_string(),
                destination: base_dir.join("wordlists/dns/subdomains-110k.txt"),
                required: false,
            },
            SeedResource {
                name: "API Endpoints".to_string(),
                resource_type: ResourceType::Wordlist,
                tier: SeedTier::Enhanced,
                url: "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt".to_string(),
                size_mb: 1,
                description: "Common API endpoints and paths".to_string(),
                destination: base_dir.join("wordlists/web/api-endpoints.txt"),
                required: false,
            },
        ]);

        // ADVANCED TIER (~2GB+)
        resources.extend(vec![
            SeedResource {
                name: "LinPEAS Binary".to_string(),
                resource_type: ResourceType::Binary,
                tier: SeedTier::Advanced,
                url: "https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh".to_string(),
                size_mb: 1,
                description: "Linux privilege escalation scanner".to_string(),
                destination: base_dir.join("binaries/linux/linpeas.sh"),
                required: false,
            },
            SeedResource {
                name: "WinPEAS Binary".to_string(),
                resource_type: ResourceType::Binary,
                tier: SeedTier::Advanced,
                url: "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe".to_string(),
                size_mb: 2,
                description: "Windows privilege escalation scanner".to_string(),
                destination: base_dir.join("binaries/windows/winpeas.exe"),
                required: false,
            },
            SeedResource {
                name: "Nmap Service Probes".to_string(),
                resource_type: ResourceType::Signature,
                tier: SeedTier::Advanced,
                url: "https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes".to_string(),
                size_mb: 1,
                description: "Nmap service detection signatures".to_string(),
                destination: base_dir.join("signatures/nmap-service-probes"),
                required: false,
            },
        ]);

        resources
    }

    /// Get all seedable resources
    pub fn resources(&self) -> &[SeedResource] {
        &self.resources
    }

    /// Get resources for a specific tier
    pub fn resources_for_tier(&self, tier: SeedTier) -> Vec<&SeedResource> {
        self.resources
            .iter()
            .filter(|r| r.tier == tier)
            .collect()
    }

    /// Get resources up to and including a tier (Basic includes Basic, Enhanced includes Basic+Enhanced, etc)
    pub fn resources_up_to_tier(&self, tier: SeedTier) -> Vec<&SeedResource> {
        self.resources
            .iter()
            .filter(|r| match tier {
                SeedTier::Basic => r.tier == SeedTier::Basic,
                SeedTier::Enhanced => {
                    r.tier == SeedTier::Basic || r.tier == SeedTier::Enhanced
                }
                SeedTier::Advanced => true, // All resources
            })
            .collect()
    }

    /// Get tier summary (count and total size)
    pub fn tier_summary(&self, tier: SeedTier) -> TierSummary {
        let resources = self.resources_for_tier(tier);
        let total_size_mb: u64 = resources.iter().map(|r| r.size_mb).sum();
        let count = resources.len();

        TierSummary {
            tier,
            count,
            total_size_mb,
        }
    }

    /// Check which resources are already seeded
    pub async fn check_status(&self) -> Vec<(String, bool)> {
        let mut status = Vec::new();
        for resource in &self.resources {
            let exists = resource.destination.exists();
            status.push((resource.name.clone(), exists));
        }
        status
    }

    /// Seed all resources with progress callback
    pub async fn seed_all<F>(&self, progress_callback: F) -> Result<SeedSummary>
    where
        F: Fn(SeedProgress) + Send + Sync,
    {
        let resources: Vec<&SeedResource> = self.resources.iter().collect();
        self.seed_resources(&resources, progress_callback).await
    }

    /// Seed resources for a specific tier
    pub async fn seed_tier<F>(&self, tier: SeedTier, progress_callback: F) -> Result<SeedSummary>
    where
        F: Fn(SeedProgress) + Send + Sync,
    {
        let resources: Vec<&SeedResource> = self.resources_up_to_tier(tier);
        self.seed_resources(&resources, progress_callback).await
    }

    /// Internal method to seed a list of resources
    async fn seed_resources<F>(&self, resources: &[&SeedResource], progress_callback: F) -> Result<SeedSummary>
    where
        F: Fn(SeedProgress) + Send + Sync,
    {
        let mut summary = SeedSummary::default();

        for resource in resources {
            let result = self.seed_resource(resource, &progress_callback).await;

            match result {
                Ok(_) => summary.succeeded.push(resource.name.clone()),
                Err(e) => {
                    if resource.required {
                        summary.failed.push((resource.name.clone(), e.to_string()));
                    } else {
                        summary.skipped.push(resource.name.clone());
                    }
                }
            }
        }

        Ok(summary)
    }

    /// Seed a single resource
    async fn seed_resource<F>(&self, resource: &SeedResource, progress_callback: F) -> Result<()>
    where
        F: Fn(SeedProgress),
    {
        // Check if already exists
        if resource.destination.exists() {
            progress_callback(SeedProgress {
                resource_name: resource.name.clone(),
                downloaded_mb: resource.size_mb as f64,
                total_mb: resource.size_mb as f64,
                percent: 100,
                status: SeedStatus::Skipped,
            });
            return Ok(());
        }

        // Create parent directory
        if let Some(parent) = resource.destination.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|e| Error::ToolExecution(format!("Failed to create directory: {}", e)))?;
        }

        // Report download starting
        progress_callback(SeedProgress {
            resource_name: resource.name.clone(),
            downloaded_mb: 0.0,
            total_mb: resource.size_mb as f64,
            percent: 0,
            status: SeedStatus::Downloading,
        });

        // Download with progress
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(600))
            .build()
            .map_err(|e| Error::Network(format!("Failed to create HTTP client: {}", e)))?;

        let response = client
            .get(&resource.url)
            .send()
            .await
            .map_err(|e| Error::Network(format!("Failed to download {}: {}", resource.name, e)))?;

        if !response.status().is_success() {
            return Err(Error::Network(format!(
                "Failed to download {}: HTTP {}",
                resource.name,
                response.status()
            )));
        }

        let total_size = response.content_length().unwrap_or(0);
        let mut file = fs::File::create(&resource.destination)
            .await
            .map_err(|e| Error::ToolExecution(format!("Failed to create file: {}", e)))?;

        let mut downloaded: u64 = 0;
        let mut stream = response.bytes_stream();
        let mut last_progress = 0;

        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| Error::Network(format!("Download interrupted: {}", e)))?;
            file.write_all(&chunk)
                .await
                .map_err(|e| Error::ToolExecution(format!("Failed to write: {}", e)))?;

            downloaded += chunk.len() as u64;

            // Report progress every 5%
            if total_size > 0 {
                let progress = ((downloaded * 100 / total_size) as u8).min(100);
                if progress >= last_progress + 5 || progress == 100 {
                    progress_callback(SeedProgress {
                        resource_name: resource.name.clone(),
                        downloaded_mb: downloaded as f64 / 1_000_000.0,
                        total_mb: total_size as f64 / 1_000_000.0,
                        percent: progress,
                        status: SeedStatus::Downloading,
                    });
                    last_progress = progress;
                }
            }
        }

        file.flush()
            .await
            .map_err(|e| Error::ToolExecution(format!("Failed to flush file: {}", e)))?;

        // Report complete
        progress_callback(SeedProgress {
            resource_name: resource.name.clone(),
            downloaded_mb: downloaded as f64 / 1_000_000.0,
            total_mb: downloaded as f64 / 1_000_000.0,
            percent: 100,
            status: SeedStatus::Complete,
        });

        Ok(())
    }

    /// Get the base resources directory
    pub fn base_dir(&self) -> &PathBuf {
        &self.base_dir
    }
}

impl Default for SeedManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Summary of a seeding operation
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SeedSummary {
    pub succeeded: Vec<String>,
    pub failed: Vec<(String, String)>,
    pub skipped: Vec<String>,
}

impl SeedSummary {
    /// Check if seeding was successful
    pub fn is_success(&self) -> bool {
        self.failed.is_empty()
    }

    /// Get total resources processed
    pub fn total(&self) -> usize {
        self.succeeded.len() + self.failed.len() + self.skipped.len()
    }
}

/// Summary of resources in a tier
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TierSummary {
    pub tier: SeedTier,
    pub count: usize,
    pub total_size_mb: u64,
}

impl TierSummary {
    /// Get a human-readable description
    pub fn description(&self) -> String {
        match self.tier {
            SeedTier::Basic => format!(
                "Basic tier: {} resources (~{}MB) - Essential wordlists, payloads, and fuzzing data",
                self.count, self.total_size_mb
            ),
            SeedTier::Enhanced => format!(
                "Enhanced tier: {} resources (~{}MB) - Nuclei templates, ExploitDB index, GeoIP",
                self.count, self.total_size_mb
            ),
            SeedTier::Advanced => format!(
                "Advanced tier: {} resources (~{}MB) - Precompiled binaries, full databases",
                self.count, self.total_size_mb
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seed_manager_creation() {
        let manager = SeedManager::new();
        assert!(!manager.resources().is_empty());
    }

    #[test]
    fn test_default_resources() {
        let manager = SeedManager::new();
        let resources = manager.resources();

        // Should have at least rockyou and common passwords
        assert!(resources.len() >= 2);

        // Check rockyou exists
        let rockyou = resources.iter().find(|r| r.name == "RockYou Wordlist");
        assert!(rockyou.is_some());
        assert!(rockyou.unwrap().required);
    }
}
