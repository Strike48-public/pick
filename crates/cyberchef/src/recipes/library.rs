//! Pre-built CyberChef recipe library for common pentest operations

use anyhow::{bail, Result};

/// Information about a recipe
#[derive(Debug, Clone)]
pub struct RecipeInfo {
    pub name: &'static str,
    pub category: &'static str,
    pub description: &'static str,
    pub example_input: &'static str,
}

/// Recipe library providing pre-built recipes for common pentest operations
pub struct RecipeLibrary;

impl RecipeLibrary {
    /// Get a recipe by name
    pub fn get(name: &str) -> Result<String> {
        match name {
            // Encoding/Decoding
            "base64_decode" => Ok(RECIPE_BASE64_DECODE.to_string()),
            "base64_encode" => Ok(RECIPE_BASE64_ENCODE.to_string()),
            "url_decode" => Ok(RECIPE_URL_DECODE.to_string()),
            "url_encode" => Ok(RECIPE_URL_ENCODE.to_string()),
            "hex_decode" => Ok(RECIPE_HEX_DECODE.to_string()),
            "hex_encode" => Ok(RECIPE_HEX_ENCODE.to_string()),

            // Hashing
            "hash_md5" => Ok(RECIPE_HASH_MD5.to_string()),
            "hash_sha1" => Ok(RECIPE_HASH_SHA1.to_string()),
            "hash_sha256" => Ok(RECIPE_HASH_SHA256.to_string()),
            "hash_all" => Ok(RECIPE_HASH_ALL.to_string()),

            // Cryptography
            "xor_bruteforce" => Ok(RECIPE_XOR_BRUTEFORCE.to_string()),
            "rot13" => Ok(RECIPE_ROT13.to_string()),

            // Data Extraction
            "extract_urls" => Ok(RECIPE_EXTRACT_URLS.to_string()),
            "extract_ips" => Ok(RECIPE_EXTRACT_IPS.to_string()),
            "extract_emails" => Ok(RECIPE_EXTRACT_EMAILS.to_string()),
            "extract_domains" => Ok(RECIPE_EXTRACT_DOMAINS.to_string()),

            // Compression
            "gzip_decompress" => Ok(RECIPE_GZIP_DECOMPRESS.to_string()),
            "zlib_decompress" => Ok(RECIPE_ZLIB_DECOMPRESS.to_string()),

            // Analysis
            "magic" => Ok(RECIPE_MAGIC.to_string()),
            "jwt_decode" => Ok(RECIPE_JWT_DECODE.to_string()),

            _ => bail!("Unknown recipe: {}", name),
        }
    }

    /// List all available recipes
    pub fn list() -> Vec<RecipeInfo> {
        vec![
            // Encoding/Decoding
            RecipeInfo {
                name: "base64_decode",
                category: "Encoding",
                description: "Decode Base64 encoded data",
                example_input: "SGVsbG8gV29ybGQ=",
            },
            RecipeInfo {
                name: "base64_encode",
                category: "Encoding",
                description: "Encode data to Base64",
                example_input: "Hello World",
            },
            RecipeInfo {
                name: "url_decode",
                category: "Encoding",
                description: "Decode URL encoded data",
                example_input: "Hello%20World%21",
            },
            RecipeInfo {
                name: "url_encode",
                category: "Encoding",
                description: "Encode data for URLs",
                example_input: "Hello World!",
            },
            RecipeInfo {
                name: "hex_decode",
                category: "Encoding",
                description: "Decode hexadecimal to text",
                example_input: "48656c6c6f",
            },
            RecipeInfo {
                name: "hex_encode",
                category: "Encoding",
                description: "Encode text to hexadecimal",
                example_input: "Hello",
            },

            // Hashing
            RecipeInfo {
                name: "hash_md5",
                category: "Hashing",
                description: "Calculate MD5 hash",
                example_input: "password123",
            },
            RecipeInfo {
                name: "hash_sha1",
                category: "Hashing",
                description: "Calculate SHA-1 hash",
                example_input: "password123",
            },
            RecipeInfo {
                name: "hash_sha256",
                category: "Hashing",
                description: "Calculate SHA-256 hash",
                example_input: "password123",
            },
            RecipeInfo {
                name: "hash_all",
                category: "Hashing",
                description: "Calculate all common hashes (MD5, SHA-1, SHA-256)",
                example_input: "password123",
            },

            // Cryptography
            RecipeInfo {
                name: "xor_bruteforce",
                category: "Cryptography",
                description: "Brute force XOR cipher with single-byte keys (1-255)",
                example_input: "\\x1c\\x00\\x1f\\x1f\\x14",
            },
            RecipeInfo {
                name: "rot13",
                category: "Cryptography",
                description: "Apply ROT13 cipher",
                example_input: "Hello World",
            },

            // Data Extraction
            RecipeInfo {
                name: "extract_urls",
                category: "Extraction",
                description: "Extract all URLs from text",
                example_input: "Check out https://example.com and http://test.org",
            },
            RecipeInfo {
                name: "extract_ips",
                category: "Extraction",
                description: "Extract all IP addresses from text",
                example_input: "Servers: 192.168.1.1 and 10.0.0.1",
            },
            RecipeInfo {
                name: "extract_emails",
                category: "Extraction",
                description: "Extract all email addresses from text",
                example_input: "Contact: admin@example.com or support@test.org",
            },
            RecipeInfo {
                name: "extract_domains",
                category: "Extraction",
                description: "Extract all domain names from text",
                example_input: "Visit example.com and test.org for more info",
            },

            // Compression
            RecipeInfo {
                name: "gzip_decompress",
                category: "Compression",
                description: "Decompress gzip compressed data",
                example_input: "(gzip compressed bytes)",
            },
            RecipeInfo {
                name: "zlib_decompress",
                category: "Compression",
                description: "Decompress zlib compressed data",
                example_input: "(zlib compressed bytes)",
            },

            // Analysis
            RecipeInfo {
                name: "magic",
                category: "Analysis",
                description: "Auto-detect encoding/compression and decode",
                example_input: "SGVsbG8gV29ybGQ=",
            },
            RecipeInfo {
                name: "jwt_decode",
                category: "Web",
                description: "Decode JWT token and display header/payload",
                // gitleaks:allow - Example JWT token for demonstration, not a real secret
                example_input: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
            },
        ]
    }

    /// Get recipes by category
    pub fn list_by_category(category: &str) -> Vec<RecipeInfo> {
        Self::list()
            .into_iter()
            .filter(|r| r.category == category)
            .collect()
    }

    /// Get all categories
    pub fn categories() -> Vec<&'static str> {
        vec![
            "Encoding",
            "Hashing",
            "Cryptography",
            "Extraction",
            "Compression",
            "Analysis",
            "Web",
        ]
    }
}

// Recipe definitions (CyberChef JSON format)

const RECIPE_BASE64_DECODE: &str = r#"[
    { "op": "From Base64", "args": ["A-Za-z0-9+/=", true, false] }
]"#;

const RECIPE_BASE64_ENCODE: &str = r#"[
    { "op": "To Base64", "args": ["A-Za-z0-9+/="] }
]"#;

const RECIPE_URL_DECODE: &str = r#"[
    { "op": "URL Decode", "args": [] }
]"#;

const RECIPE_URL_ENCODE: &str = r#"[
    { "op": "URL Encode", "args": [true] }
]"#;

const RECIPE_HEX_DECODE: &str = r#"[
    { "op": "From Hex", "args": ["Auto"] }
]"#;

const RECIPE_HEX_ENCODE: &str = r#"[
    { "op": "To Hex", "args": ["None", 0] }
]"#;

const RECIPE_HASH_MD5: &str = r#"[
    { "op": "MD5", "args": [] }
]"#;

const RECIPE_HASH_SHA1: &str = r#"[
    { "op": "SHA1", "args": [] }
]"#;

const RECIPE_HASH_SHA256: &str = r#"[
    { "op": "SHA2", "args": ["256"] }
]"#;

const RECIPE_HASH_ALL: &str = r#"[
    { "op": "MD5", "args": [] },
    { "op": "Label", "args": ["MD5: "] },
    { "op": "Register", "args": ["(.+)", true, false, false] },
    { "op": "SHA1", "args": [] },
    { "op": "Label", "args": ["SHA1: "] },
    { "op": "Register", "args": ["(.+)", true, false, false] },
    { "op": "SHA2", "args": ["256"] },
    { "op": "Label", "args": ["SHA256: "] }
]"#;

const RECIPE_XOR_BRUTEFORCE: &str = r#"[
    { "op": "XOR Brute Force", "args": [1, 100, 0, "Standard", false, false, false, false] }
]"#;

const RECIPE_ROT13: &str = r#"[
    { "op": "ROT13", "args": [true, true, false, 13] }
]"#;

const RECIPE_EXTRACT_URLS: &str = r#"[
    { "op": "Extract URLs", "args": [false, false, false] }
]"#;

const RECIPE_EXTRACT_IPS: &str = r#"[
    { "op": "Extract IP addresses", "args": [true, true, true] }
]"#;

const RECIPE_EXTRACT_EMAILS: &str = r#"[
    { "op": "Extract email addresses", "args": [false] }
]"#;

const RECIPE_EXTRACT_DOMAINS: &str = r#"[
    { "op": "Extract domains", "args": [true] }
]"#;

const RECIPE_GZIP_DECOMPRESS: &str = r#"[
    { "op": "Gunzip", "args": [] }
]"#;

const RECIPE_ZLIB_DECOMPRESS: &str = r#"[
    { "op": "Zlib Inflate", "args": [0, 0, "Adaptive", false, false] }
]"#;

const RECIPE_MAGIC: &str = r#"[
    { "op": "Magic", "args": [3, false, false, ""] }
]"#;

const RECIPE_JWT_DECODE: &str = r#"[
    { "op": "JWT Decode", "args": [] }
]"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_recipe() {
        let recipe = RecipeLibrary::get("base64_decode").unwrap();
        assert!(recipe.contains("From Base64"));
    }

    #[test]
    fn test_unknown_recipe() {
        let result = RecipeLibrary::get("nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_list_recipes() {
        let recipes = RecipeLibrary::list();
        assert!(recipes.len() >= 20);
        assert!(recipes.iter().any(|r| r.name == "base64_decode"));
    }

    #[test]
    fn test_list_by_category() {
        let encoding = RecipeLibrary::list_by_category("Encoding");
        assert!(!encoding.is_empty());
        assert!(encoding.iter().all(|r| r.category == "Encoding"));
    }

    #[test]
    fn test_categories() {
        let categories = RecipeLibrary::categories();
        assert!(categories.contains(&"Encoding"));
        assert!(categories.contains(&"Hashing"));
    }
}
