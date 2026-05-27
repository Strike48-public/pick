//! Webwright workspace management.
//!
//! Handles creation of temp directories, config YAML writing,
//! script file writing, and post-execution artifact collection.

use pentest_core::error::{Error, Result};
use pentest_platform::CommandExec;
use serde_json::Value;
use uuid::Uuid;

use super::config::WebwrightConfig;

/// Manages a Webwright execution workspace.
pub struct WebwrightWorkspace {
    /// Unique task ID for this execution.
    pub task_id: String,
    /// Base directory path inside the sandbox.
    base_dir: String,
}

impl WebwrightWorkspace {
    /// Create a new workspace directory.
    ///
    /// Uses direct filesystem access (not platform.execute_command) because
    /// workspace files are written from the host via std::fs::write and must
    /// be accessible from both the host (for writing config/scripts and
    /// collecting artifacts) and the sandbox (for running Python).
    pub async fn create(_platform: &impl CommandExec) -> Result<Self> {
        let task_id = Uuid::new_v4().to_string();
        let base_dir = format!("/tmp/webwright/{}", task_id);

        std::fs::create_dir_all(&base_dir)
            .map_err(|e| Error::ToolExecution(format!("Failed to create workspace: {}", e)))?;

        Ok(Self { task_id, base_dir })
    }

    /// Write Webwright YAML config to workspace.
    pub async fn write_config(&self, proxy_port: u16, model_name: &str) -> Result<()> {
        let config = WebwrightConfig::new(proxy_port, model_name);
        let yaml = config
            .to_yaml()
            .map_err(|e| Error::ToolExecution(format!("Failed to serialize config: {}", e)))?;

        std::fs::write(format!("{}/config.yaml", self.base_dir), yaml.as_bytes())
            .map_err(|e| Error::ToolExecution(format!("Failed to write config: {}", e)))?;

        Ok(())
    }

    /// Write a Python script to workspace for execute mode.
    pub async fn write_script(&self, content: &str) -> Result<()> {
        std::fs::write(format!("{}/script.py", self.base_dir), content.as_bytes())
            .map_err(|e| Error::ToolExecution(format!("Failed to write script: {}", e)))?;

        Ok(())
    }

    /// Config file path inside the workspace.
    pub fn config_path(&self) -> String {
        format!("{}/config.yaml", self.base_dir)
    }

    /// Script file path inside the workspace.
    pub fn script_path(&self) -> String {
        format!("{}/script.py", self.base_dir)
    }

    /// Base workspace path.
    pub fn path(&self) -> String {
        self.base_dir.clone()
    }

    /// Collect all artifacts produced by Webwright in the workspace.
    ///
    /// Walks the workspace directory and categorizes files by type.
    pub async fn collect_artifacts(&self, _platform: &impl CommandExec) -> Result<Value> {
        let mut scripts = Vec::new();
        let mut screenshots = Vec::new();
        let mut logs = Vec::new();
        let mut snapshots = Vec::new();
        let mut other = Vec::new();
        let mut total_files = 0;

        fn walk_dir(dir: &std::path::Path, files: &mut Vec<String>) {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        walk_dir(&path, files);
                    } else if let Some(s) = path.to_str() {
                        files.push(s.to_string());
                    }
                }
            }
        }

        let mut all_files = Vec::new();
        walk_dir(std::path::Path::new(&self.base_dir), &mut all_files);

        for file in &all_files {
            let filename = file.rsplit('/').next().unwrap_or(file);
            if filename.ends_with(".py") && filename != "script.py" {
                scripts.push(file.as_str());
            } else if filename.contains("screenshot") && filename.ends_with(".png") {
                screenshots.push(file.as_str());
            } else if filename.ends_with(".json") || filename.ends_with(".log") {
                logs.push(file.as_str());
            } else if filename.ends_with(".html") {
                snapshots.push(file.as_str());
            } else if filename != "config.yaml" && filename != "script.py" {
                other.push(file.as_str());
            }
            total_files += 1;
        }

        Ok(serde_json::json!({
            "workspace": self.base_dir,
            "task_id": self.task_id,
            "scripts": scripts,
            "screenshots": screenshots,
            "logs": logs,
            "dom_snapshots": snapshots,
            "other": other,
            "total_files": total_files,
        }))
    }

    /// Clean up workspace directory.
    pub async fn cleanup(&self, _platform: &impl CommandExec) -> Result<()> {
        let _ = std::fs::remove_dir_all(&self.base_dir);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_paths_are_consistent() {
        let ws = WebwrightWorkspace {
            task_id: "test-123".to_string(),
            base_dir: "/tmp/webwright/test-123".to_string(),
        };
        assert_eq!(ws.config_path(), "/tmp/webwright/test-123/config.yaml");
        assert_eq!(ws.script_path(), "/tmp/webwright/test-123/script.py");
        assert_eq!(ws.path(), "/tmp/webwright/test-123");
    }
}
