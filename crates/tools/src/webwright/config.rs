//! Webwright YAML configuration generation.

use serde::Serialize;

/// Webwright model configuration (OpenAI-compatible endpoint).
#[derive(Debug, Clone, Serialize)]
pub struct WebwrightModelConfig {
    pub provider: String,
    pub base_url: String,
    pub api_key: String,
    pub model: String,
}

/// Top-level Webwright config written to workspace as YAML.
#[derive(Debug, Clone, Serialize)]
pub struct WebwrightConfig {
    pub model: WebwrightModelConfig,
}

impl WebwrightConfig {
    /// Create config pointing at Pick's local LLM proxy.
    pub fn new(proxy_port: u16, model_name: &str) -> Self {
        Self {
            model: WebwrightModelConfig {
                provider: "openai".to_string(),
                base_url: format!("http://127.0.0.1:{}/v1", proxy_port),
                api_key: "pick-internal".to_string(),
                model: model_name.to_string(),
            },
        }
    }

    /// Serialize to YAML string for writing to workspace.
    pub fn to_yaml(&self) -> Result<String, serde_yaml::Error> {
        serde_yaml::to_string(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_serializes_to_yaml() {
        let config = WebwrightConfig::new(9100, "strike48-default");
        let yaml = config.to_yaml().unwrap();
        assert!(yaml.contains("provider: openai"));
        assert!(yaml.contains("http://127.0.0.1:9100/v1"));
        assert!(yaml.contains("model: strike48-default"));
    }
}
