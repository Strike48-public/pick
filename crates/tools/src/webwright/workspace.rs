//! Webwright workspace management.
//!
//! The sandbox bind-mounts the connector workspace to `/workspace` inside proot.
//! We create a subdir there so artifacts show up in the Files panel and are
//! servable via the existing workspace file routes.

use pentest_core::error::{Error, Result};
use pentest_platform::CommandExec;
use serde_json::Value;
use uuid::Uuid;

use super::config::WebwrightConfig;

/// Manages a Webwright execution workspace.
pub struct WebwrightWorkspace {
    /// Unique task ID for this execution.
    pub task_id: String,
    /// Path inside the sandbox (what we pass to webwright as --output-dir).
    sandbox_dir: String,
    /// Path on the host (where we read artifacts back from).
    host_dir: String,
}

impl WebwrightWorkspace {
    /// Create a new workspace directory.
    ///
    /// Creates `webwright/<task-id>/` inside the connector workspace on the host.
    /// Inside proot this is accessible at `/workspace/webwright/<task-id>/`.
    pub async fn create(_platform: &impl CommandExec) -> Result<Self> {
        let task_id = Uuid::new_v4().to_string();

        let host_dir = pentest_core::workspace::workspace_root()
            .join("webwright")
            .join(&task_id);
        std::fs::create_dir_all(&host_dir)
            .map_err(|e| Error::ToolExecution(format!("Failed to create workspace: {}", e)))?;

        // Inside proot, the connector workspace is bind-mounted at /workspace
        let sandbox_dir = format!("/workspace/webwright/{}", task_id);

        Ok(Self {
            task_id,
            sandbox_dir,
            host_dir: host_dir.to_string_lossy().to_string(),
        })
    }

    /// Write Webwright YAML config to workspace (host side).
    pub async fn write_config(&self, proxy_port: u16, model_name: &str) -> Result<()> {
        let config = WebwrightConfig::new(proxy_port, model_name);
        let yaml = config
            .to_yaml()
            .map_err(|e| Error::ToolExecution(format!("Failed to serialize config: {}", e)))?;

        std::fs::write(format!("{}/config.yaml", self.host_dir), yaml.as_bytes())
            .map_err(|e| Error::ToolExecution(format!("Failed to write config: {}", e)))?;

        Ok(())
    }

    /// Write a Python script to workspace (host side).
    pub async fn write_script(&self, content: &str) -> Result<()> {
        std::fs::write(format!("{}/script.py", self.host_dir), content.as_bytes())
            .map_err(|e| Error::ToolExecution(format!("Failed to write script: {}", e)))?;

        Ok(())
    }

    /// Config file path inside the sandbox.
    pub fn config_path(&self) -> String {
        format!("{}/config.yaml", self.sandbox_dir)
    }

    /// Script file path inside the sandbox.
    pub fn script_path(&self) -> String {
        format!("{}/script.py", self.sandbox_dir)
    }

    /// Output dir path inside the sandbox (for --output-dir flag).
    pub fn path(&self) -> String {
        self.sandbox_dir.clone()
    }

    /// Host-side path (for reading artifacts after execution).
    pub fn host_path(&self) -> &str {
        &self.host_dir
    }

    /// Collect all artifacts produced by Webwright in the workspace.
    /// Reads from the host-side path.
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
        walk_dir(std::path::Path::new(&self.host_dir), &mut all_files);

        for file in &all_files {
            let filename = file.rsplit('/').next().unwrap_or(file);
            if filename.ends_with(".py") && filename != "script.py" {
                scripts.push(file.as_str());
            } else if filename.ends_with(".png") {
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
            "workspace": self.host_dir,
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
        let _ = std::fs::remove_dir_all(&self.host_dir);
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
            sandbox_dir: "/workspace/webwright/test-123".to_string(),
            host_dir: "/home/user/.local/share/pentest-connector/workspaces/webwright/test-123"
                .to_string(),
        };
        assert_eq!(ws.config_path(), "/workspace/webwright/test-123/config.yaml");
        assert_eq!(ws.script_path(), "/workspace/webwright/test-123/script.py");
        assert_eq!(ws.path(), "/workspace/webwright/test-123");
        assert_eq!(
            ws.host_path(),
            "/home/user/.local/share/pentest-connector/workspaces/webwright/test-123"
        );
    }
}
