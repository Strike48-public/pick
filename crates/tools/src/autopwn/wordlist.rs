//! Wordlist management for password cracking

use pentest_core::error::{Error, Result};
use std::path::PathBuf;
use tokio::fs;
use tokio::io::AsyncWriteExt;

/// Wordlist metadata
pub struct Wordlist {
    pub name: &'static str,
    pub filename: &'static str,
    pub url: &'static str,
    pub size_mb: u64,
    pub description: &'static str,
}

/// Common wordlists
pub const ROCKYOU: Wordlist = Wordlist {
    name: "RockYou",
    filename: "rockyou.txt",
    url: "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt",
    size_mb: 134,
    description: "14M passwords from RockYou breach (most common)",
};

pub const COMMON_PASSWORDS: Wordlist = Wordlist {
    name: "Common Passwords",
    filename: "common-passwords.txt",
    url: "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-100000.txt",
    size_mb: 1,
    description: "Top 100k most common passwords",
};

/// Get wordlist directory
pub fn get_wordlist_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".pick").join("wordlists")
}

/// Check if wordlist exists
#[allow(dead_code)]
pub async fn wordlist_exists(wordlist: &Wordlist) -> bool {
    let path = get_wordlist_dir().join(wordlist.filename);
    path.exists()
}

/// Get path to wordlist (creates directory if needed)
pub async fn get_wordlist_path(wordlist: &Wordlist) -> Result<PathBuf> {
    let dir = get_wordlist_dir();
    fs::create_dir_all(&dir)
        .await
        .map_err(|e| Error::ToolExecution(format!("Failed to create wordlist directory: {}", e)))?;

    Ok(dir.join(wordlist.filename))
}

/// Download wordlist with progress updates
pub async fn download_wordlist(wordlist: &Wordlist) -> Result<PathBuf> {
    tracing::info!("");
    tracing::info!("📥 Downloading Wordlist: {}", wordlist.name);
    tracing::info!("───────────────────────────────────────────────────");
    tracing::info!("  File:        {}", wordlist.filename);
    tracing::info!("  Size:        ~{} MB", wordlist.size_mb);
    tracing::info!("  Source:      {}", wordlist.url);
    tracing::info!("  Description: {}", wordlist.description);
    tracing::info!("");

    let path = get_wordlist_path(wordlist).await?;

    // Check if already exists
    if path.exists() {
        tracing::info!("✓ Wordlist already exists: {}", path.display());
        return Ok(path);
    }

    tracing::info!("⏳ Downloading {} MB...", wordlist.size_mb);
    tracing::info!("   This may take a few minutes...");

    // Download with reqwest
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(600)) // 10 min timeout
        .build()
        .map_err(|e| Error::Network(format!("Failed to create HTTP client: {}", e)))?;

    let response = client
        .get(wordlist.url)
        .send()
        .await
        .map_err(|e| Error::Network(format!("Failed to download wordlist: {}", e)))?;

    if !response.status().is_success() {
        return Err(Error::Network(format!(
            "Failed to download wordlist: HTTP {}",
            response.status()
        )));
    }

    // Get total size
    let total_size = response.content_length().unwrap_or(0);

    // Download in chunks with progress
    let mut file = fs::File::create(&path)
        .await
        .map_err(|e| Error::ToolExecution(format!("Failed to create wordlist file: {}", e)))?;

    let mut downloaded: u64 = 0;
    let mut stream = response.bytes_stream();
    let mut last_progress = 0;

    use futures::StreamExt;

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| Error::Network(format!("Download interrupted: {}", e)))?;
        file.write_all(&chunk)
            .await
            .map_err(|e| Error::ToolExecution(format!("Failed to write wordlist: {}", e)))?;

        downloaded += chunk.len() as u64;

        // Log progress every 10%
        if total_size > 0 {
            let progress = (downloaded * 100 / total_size) as u32;
            if progress >= last_progress + 10 {
                tracing::info!("   {}% complete ({} MB / {} MB)",
                    progress,
                    downloaded / 1_000_000,
                    total_size / 1_000_000
                );
                last_progress = progress;
            }
        }
    }

    file.flush()
        .await
        .map_err(|e| Error::ToolExecution(format!("Failed to flush wordlist file: {}", e)))?;

    tracing::info!("");
    tracing::info!("✓ Download complete: {}", path.display());
    tracing::info!("  Size: {} MB", downloaded / 1_000_000);

    Ok(path)
}

/// Ensure wordlist is available (download if needed)
pub async fn ensure_wordlist(wordlist: &Wordlist) -> Result<PathBuf> {
    let path = get_wordlist_path(wordlist).await?;

    if path.exists() {
        tracing::info!("✓ Using wordlist: {}", path.display());
        Ok(path)
    } else {
        tracing::info!("⚠ Wordlist not found, downloading...");
        download_wordlist(wordlist).await
    }
}

/// List available wordlists
#[allow(dead_code)]
pub async fn list_wordlists() -> Vec<(String, bool)> {
    let mut lists = Vec::new();

    for wordlist in &[ROCKYOU, COMMON_PASSWORDS] {
        let exists = wordlist_exists(wordlist).await;
        lists.push((wordlist.name.to_string(), exists));
    }

    lists
}
