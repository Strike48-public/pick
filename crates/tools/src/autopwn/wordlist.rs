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
    // Note: This is a placeholder URL. Users should install wordlists locally:
    // Debian/Ubuntu: sudo apt install wordlists
    // Or download manually to /usr/share/wordlists/
    url: "https://download.weakpass.com/wordlists/90/rockyou.txt.gz",
    size_mb: 60,
    description: "14M passwords from RockYou breach (most common)",
};

pub const COMMON_PASSWORDS: Wordlist = Wordlist {
    name: "Common Passwords",
    filename: "common-passwords.txt",
    // Using a smaller, more reliable wordlist for quick testing
    url: "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt",
    size_mb: 1,
    description: "Top 10k most common passwords",
};

/// Get wordlist directory
pub fn get_wordlist_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".pick").join("wordlists")
}

/// Common wordlist locations (in priority order)
/// Includes Pick's own resources directory first for seeded wordlists
fn get_wordlist_search_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    // 1. Pick's resources directory (seeded wordlists)
    if let Ok(home) = std::env::var("HOME") {
        paths.push(PathBuf::from(home).join(".pick/resources/wordlists"));
    }

    // 2. System wordlist locations
    paths.push(PathBuf::from("/usr/share/wordlists"));
    paths.push(PathBuf::from("/usr/share/seclists/Passwords"));
    paths.push(PathBuf::from("/opt/wordlists"));
    paths.push(PathBuf::from("/usr/local/share/wordlists"));

    paths
}

/// Search for wordlist in Pick's resources and system locations
pub async fn find_system_wordlist(filename: &str) -> Option<PathBuf> {
    let search_paths = get_wordlist_search_paths();

    // Try exact filename first
    for base_path in &search_paths {
        let path = base_path.join(filename);
        if path.exists() {
            tracing::info!("✓ Found wordlist: {}", path.display());
            return Some(path);
        }
    }

    // Try compressed versions (.gz, .bz2)
    for base_path in &search_paths {
        for ext in &[".gz", ".bz2"] {
            let compressed_path = base_path.join(format!("{}{}", filename, ext));
            if compressed_path.exists() {
                tracing::info!("✓ Found compressed wordlist: {}", compressed_path.display());
                // Decompress to Pick's wordlist directory
                if let Ok(decompressed) = decompress_wordlist(&compressed_path, filename).await {
                    return Some(decompressed);
                }
            }
        }
    }

    None
}

/// Decompress a wordlist to Pick's directory
async fn decompress_wordlist(compressed_path: &PathBuf, filename: &str) -> Result<PathBuf> {
    let output_path = get_wordlist_dir().join(filename);

    // Create directory if needed
    fs::create_dir_all(&get_wordlist_dir())
        .await
        .map_err(|e| Error::ToolExecution(format!("Failed to create wordlist directory: {}", e)))?;

    tracing::info!(
        "⏳ Decompressing {} to {}",
        compressed_path.display(),
        output_path.display()
    );

    // Decompress based on extension
    let success = if compressed_path.extension().and_then(|s| s.to_str()) == Some("gz") {
        // Use gunzip command
        let output = tokio::process::Command::new("gunzip")
            .arg("-c")
            .arg(compressed_path)
            .output()
            .await
            .map_err(|e| Error::ToolExecution(format!("Failed to run gunzip: {}", e)))?;

        if output.status.success() {
            fs::write(&output_path, output.stdout).await.map_err(|e| {
                Error::ToolExecution(format!("Failed to write decompressed file: {}", e))
            })?;
            true
        } else {
            false
        }
    } else if compressed_path.extension().and_then(|s| s.to_str()) == Some("bz2") {
        // Use bunzip2 command
        let output = tokio::process::Command::new("bunzip2")
            .arg("-c")
            .arg(compressed_path)
            .output()
            .await
            .map_err(|e| Error::ToolExecution(format!("Failed to run bunzip2: {}", e)))?;

        if output.status.success() {
            fs::write(&output_path, output.stdout).await.map_err(|e| {
                Error::ToolExecution(format!("Failed to write decompressed file: {}", e))
            })?;
            true
        } else {
            false
        }
    } else {
        false
    };

    if success {
        tracing::info!("✓ Decompressed to: {}", output_path.display());
        Ok(output_path)
    } else {
        Err(Error::ToolExecution("Decompression failed".into()))
    }
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
        let status = response.status();
        tracing::error!("✗ Download failed: HTTP {}", status);
        tracing::error!("");
        tracing::error!("Next steps:");
        tracing::error!("  1. Check internet connection");
        tracing::error!("  2. Install wordlist manually:");
        tracing::error!(
            "     wget {} -O /usr/share/wordlists/{}",
            wordlist.url,
            wordlist.filename
        );
        tracing::error!("  3. Or use a custom wordlist with 'wordlist' parameter");
        tracing::error!("");

        return Err(Error::Network(format!(
            "Failed to download wordlist: HTTP {}. See logs for next steps.",
            status
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
        if let Some(progress) = (downloaded * 100).checked_div(total_size) {
            let progress = progress as u32;
            if progress >= last_progress + 10 {
                tracing::info!(
                    "   {}% complete ({} MB / {} MB)",
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

/// Ensure wordlist is available (check system, then cache, then download)
pub async fn ensure_wordlist(wordlist: &Wordlist) -> Result<PathBuf> {
    // 1. Check Pick's cache directory first
    let cache_path = get_wordlist_path(wordlist).await?;
    if cache_path.exists() {
        tracing::info!("✓ Using cached wordlist: {}", cache_path.display());
        return Ok(cache_path);
    }

    // 2. Search common system locations
    tracing::info!("🔍 Searching system wordlist paths...");
    if let Some(system_path) = find_system_wordlist(wordlist.filename).await {
        return Ok(system_path);
    }

    // 3. Download as last resort
    tracing::info!("⚠ Wordlist not found locally, downloading...");
    tracing::info!("");
    tracing::info!("💡 Tip: Install wordlists locally for faster access:");
    tracing::info!("   sudo apt install wordlists  (Debian/Ubuntu)");
    tracing::info!("   Or download to /usr/share/wordlists/");
    tracing::info!("");

    download_wordlist(wordlist).await
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
