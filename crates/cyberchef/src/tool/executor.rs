//! CyberChef recipe executor
//!
//! This module handles the execution of CyberChef recipes. For the MVP, it provides
//! a Rust-only implementation of common operations with plans for Node.js bridge integration.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::time::Instant;

/// Result of a recipe execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    /// Output data after recipe execution
    pub output: String,
    /// Output type/format
    pub output_type: String,
    /// Execution duration in milliseconds
    pub duration_ms: u64,
}

/// Recipe executor that processes CyberChef recipes
pub struct RecipeExecutor;

impl RecipeExecutor {
    pub fn new() -> Self {
        Self
    }

    /// Execute a CyberChef recipe on input data
    ///
    /// # Arguments
    /// * `recipe_json` - CyberChef recipe in JSON format
    /// * `input` - Input data to process
    /// * `input_type` - Input format: "string", "hex", "base64"
    ///
    /// # Returns
    /// Execution result with output data and metadata
    pub async fn execute(
        &self,
        recipe_json: &str,
        input: &str,
        _input_type: &str,
    ) -> Result<ExecutionResult> {
        let start = Instant::now();

        // Parse recipe to determine operations
        let recipe: serde_json::Value = serde_json::from_str(recipe_json)?;
        let ops = recipe
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("Recipe must be an array of operations"))?;

        if ops.is_empty() {
            bail!("Recipe contains no operations");
        }

        // For MVP: Implement basic operations in Rust
        let mut current_data = input.to_string();

        for op in ops {
            let op_name = op
                .get("op")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("Operation missing 'op' field"))?;

            current_data = match op_name {
                "From Base64" => self.from_base64(&current_data)?,
                "To Base64" => self.to_base64(&current_data)?,
                "From Hex" => self.from_hex(&current_data)?,
                "To Hex" => self.to_hex(&current_data)?,
                "URL Decode" => self.url_decode(&current_data)?,
                "URL Encode" => self.url_encode(&current_data)?,
                "MD5" => self.md5(&current_data)?,
                "SHA1" => self.sha1(&current_data)?,
                "SHA2" => {
                    let args = op.get("args").and_then(|v| v.as_array());
                    let bits = args
                        .and_then(|a| a.get(0))
                        .and_then(|v| v.as_str())
                        .unwrap_or("256");
                    self.sha2(&current_data, bits)?
                }
                "ROT13" => self.rot13(&current_data)?,
                _ => {
                    // For unsupported operations, provide helpful error
                    bail!(
                        "Operation '{}' not yet implemented in Rust executor. \
                         Supported operations: From/To Base64, From/To Hex, URL Encode/Decode, \
                         MD5, SHA1, SHA2, ROT13. \
                         Future versions will support all CyberChef operations via Node.js bridge.",
                        op_name
                    )
                }
            };
        }

        let duration_ms = start.elapsed().as_millis() as u64;

        Ok(ExecutionResult {
            output: current_data,
            output_type: "string".to_string(),
            duration_ms,
        })
    }

    // Rust implementations of common operations

    fn from_base64(&self, input: &str) -> Result<String> {
        use base64::{engine::general_purpose, Engine};
        let bytes = general_purpose::STANDARD
            .decode(input.trim())
            .map_err(|e| anyhow::anyhow!("Base64 decode error: {}", e))?;
        Ok(String::from_utf8_lossy(&bytes).to_string())
    }

    fn to_base64(&self, input: &str) -> Result<String> {
        use base64::{engine::general_purpose, Engine};
        Ok(general_purpose::STANDARD.encode(input.as_bytes()))
    }

    fn from_hex(&self, input: &str) -> Result<String> {
        let clean = input.trim().replace(" ", "").replace("0x", "");
        let bytes = hex::decode(&clean).map_err(|e| anyhow::anyhow!("Hex decode error: {}", e))?;
        Ok(String::from_utf8_lossy(&bytes).to_string())
    }

    fn to_hex(&self, input: &str) -> Result<String> {
        Ok(hex::encode(input.as_bytes()))
    }

    fn url_decode(&self, input: &str) -> Result<String> {
        urlencoding::decode(input)
            .map(|s| s.to_string())
            .map_err(|e| anyhow::anyhow!("URL decode error: {}", e))
    }

    fn url_encode(&self, input: &str) -> Result<String> {
        Ok(urlencoding::encode(input).to_string())
    }

    fn md5(&self, input: &str) -> Result<String> {
        let digest = md5::compute(input.as_bytes());
        Ok(format!("{:x}", digest))
    }

    fn sha1(&self, input: &str) -> Result<String> {
        use sha1::{Digest, Sha1};
        let mut hasher = Sha1::new();
        hasher.update(input.as_bytes());
        Ok(format!("{:x}", hasher.finalize()))
    }

    fn sha2(&self, input: &str, bits: &str) -> Result<String> {
        use sha2::{Digest, Sha256, Sha512};

        match bits {
            "256" => {
                let mut hasher = Sha256::new();
                hasher.update(input.as_bytes());
                Ok(format!("{:x}", hasher.finalize()))
            }
            "512" => {
                let mut hasher = Sha512::new();
                hasher.update(input.as_bytes());
                Ok(format!("{:x}", hasher.finalize()))
            }
            _ => bail!("Unsupported SHA2 bit length: {}", bits),
        }
    }

    fn rot13(&self, input: &str) -> Result<String> {
        Ok(input
            .chars()
            .map(|c| {
                if c.is_ascii_alphabetic() {
                    let base = if c.is_ascii_lowercase() { b'a' } else { b'A' };
                    let offset = (c as u8 - base + 13) % 26;
                    (base + offset) as char
                } else {
                    c
                }
            })
            .collect())
    }
}

impl Default for RecipeExecutor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_base64_decode() {
        let executor = RecipeExecutor::new();
        let recipe = r#"[{ "op": "From Base64", "args": [] }]"#;
        let result = executor
            .execute(recipe, "SGVsbG8gV29ybGQ=", "string")
            .await
            .unwrap();
        assert_eq!(result.output, "Hello World");
    }

    #[tokio::test]
    async fn test_base64_encode() {
        let executor = RecipeExecutor::new();
        let recipe = r#"[{ "op": "To Base64", "args": [] }]"#;
        let result = executor
            .execute(recipe, "Hello World", "string")
            .await
            .unwrap();
        assert_eq!(result.output, "SGVsbG8gV29ybGQ=");
    }

    #[tokio::test]
    async fn test_md5_hash() {
        let executor = RecipeExecutor::new();
        let recipe = r#"[{ "op": "MD5", "args": [] }]"#;
        let result = executor
            .execute(recipe, "password123", "string")
            .await
            .unwrap();
        assert_eq!(result.output.len(), 32); // MD5 is 32 hex chars
    }

    #[tokio::test]
    async fn test_chained_operations() {
        let executor = RecipeExecutor::new();
        let recipe = r#"[
            { "op": "To Base64", "args": [] },
            { "op": "From Base64", "args": [] }
        ]"#;
        let result = executor.execute(recipe, "Hello", "string").await.unwrap();
        assert_eq!(result.output, "Hello");
    }

    #[tokio::test]
    async fn test_rot13() {
        let executor = RecipeExecutor::new();
        let recipe = r#"[{ "op": "ROT13", "args": [] }]"#;
        let result = executor
            .execute(recipe, "Hello World", "string")
            .await
            .unwrap();
        assert_eq!(result.output, "Uryyb Jbeyq");
    }

    #[tokio::test]
    async fn test_url_encode_decode() {
        let executor = RecipeExecutor::new();
        let recipe = r#"[
            { "op": "URL Encode", "args": [] },
            { "op": "URL Decode", "args": [] }
        ]"#;
        let result = executor
            .execute(recipe, "Hello World!", "string")
            .await
            .unwrap();
        assert_eq!(result.output, "Hello World!");
    }

    #[tokio::test]
    async fn test_unsupported_operation() {
        let executor = RecipeExecutor::new();
        let recipe = r#"[{ "op": "Gunzip", "args": [] }]"#;
        let result = executor.execute(recipe, "test", "string").await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("not yet implemented"));
    }
}
