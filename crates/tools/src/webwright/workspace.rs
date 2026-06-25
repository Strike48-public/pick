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
    /// Path on the host where rootfs /tmp maps to.
    host_dir: String,
    /// Path in connector workspace (for Files panel). Artifacts copied here after.
    connector_dir: Option<String>,
}

impl WebwrightWorkspace {
    /// Create a new workspace directory.
    ///
    /// Uses /tmp/webwright/ which is accessible inside proot (rootfs /tmp).
    /// After execution, artifacts are copied to the connector workspace for
    /// the Files panel.
    pub async fn create(
        _platform: &impl CommandExec,
        connector_workspace: Option<&std::path::Path>,
    ) -> Result<Self> {
        let task_id = Uuid::new_v4().to_string();

        // Sandbox dir: accessible inside proot via rootfs /tmp
        let sandbox_dir = format!("/tmp/webwright/{}", task_id);

        // Host dir: where artifacts actually land (rootfs path on host)
        let rootfs_str = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        let rootfs_host_path = format!(
            "{}/.local/share/pentest-sandbox/blackarch-rootfs/tmp/webwright/{}",
            rootfs_str, task_id
        );

        // Also create in connector workspace (for Files panel) — we'll copy after
        let connector_dir = connector_workspace.map(|ws| ws.join("webwright").join(&task_id));
        if let Some(ref cd) = connector_dir {
            std::fs::create_dir_all(cd)
                .map_err(|e| Error::ToolExecution(format!("Failed to create workspace: {}", e)))?;
        }

        Ok(Self {
            task_id,
            sandbox_dir,
            host_dir: rootfs_host_path,
            connector_dir: connector_dir.map(|p| p.to_string_lossy().to_string()),
        })
    }

    /// Write Webwright YAML config to workspace (host-side rootfs path).
    pub async fn write_config(&self, proxy_port: u16, model_name: &str) -> Result<()> {
        let config = WebwrightConfig::new(proxy_port, model_name);
        let yaml = config
            .to_yaml()
            .map_err(|e| Error::ToolExecution(format!("Failed to serialize config: {}", e)))?;

        // Write to the rootfs host path (visible inside proot as sandbox_dir)
        std::fs::create_dir_all(&self.host_dir)
            .map_err(|e| Error::ToolExecution(format!("Failed to create dir: {}", e)))?;
        std::fs::write(format!("{}/config.yaml", self.host_dir), yaml.as_bytes())
            .map_err(|e| Error::ToolExecution(format!("Failed to write config: {}", e)))?;

        Ok(())
    }

    /// Write a Python script to workspace (host-side rootfs path).
    pub async fn write_script(&self, content: &str) -> Result<()> {
        std::fs::create_dir_all(&self.host_dir)
            .map_err(|e| Error::ToolExecution(format!("Failed to create dir: {}", e)))?;
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
        let mut scripts: Vec<String> = Vec::new();
        let mut screenshots: Vec<String> = Vec::new();
        let mut logs: Vec<String> = Vec::new();
        let mut snapshots: Vec<String> = Vec::new();
        let mut other: Vec<String> = Vec::new();
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

        // Read from connector workspace if copy succeeded, otherwise rootfs host path
        let read_dir = self.connector_dir.as_deref().unwrap_or(&self.host_dir);
        let mut all_files = Vec::new();
        walk_dir(std::path::Path::new(read_dir), &mut all_files);

        // Return paths relative to the connector workspace root.
        // read_file resolves relative to the workspace, so "webwright/<id>/file.png" works.
        for file in &all_files {
            let relative = file
                .strip_prefix(read_dir)
                .unwrap_or(file)
                .trim_start_matches('/');

            // Path that read_file can access (relative to workspace root)
            let visible_path = match &self.connector_dir {
                Some(_) => format!("webwright/{}/{}", self.task_id, relative),
                None => relative.to_string(),
            };

            let filename = file.rsplit('/').next().unwrap_or(file);
            if filename.ends_with(".py") && filename != "script.py" {
                scripts.push(visible_path.clone());
            } else if filename.ends_with(".png")
                || filename.ends_with(".jpg")
                || filename.ends_with(".jpeg")
            {
                screenshots.push(visible_path.clone());
            } else if filename.ends_with(".json") || filename.ends_with(".log") {
                logs.push(visible_path.clone());
            } else if filename.ends_with(".html") {
                snapshots.push(visible_path.clone());
            } else if filename != "config.yaml" && filename != "script.py" {
                other.push(visible_path.clone());
            }
            total_files += 1;
        }

        Ok(serde_json::json!({
            "workspace": format!("webwright/{}", self.task_id),
            "task_id": self.task_id,
            "scripts": scripts,
            "screenshots": screenshots,
            "logs": logs,
            "dom_snapshots": snapshots,
            "other": other,
            "total_files": total_files,
        }))
    }

    /// Copy artifacts from rootfs /tmp to the connector workspace (for Files panel + read_file).
    pub fn copy_to_connector_workspace(&self) {
        if let Some(ref dest) = self.connector_dir {
            fn copy_dir(src: &std::path::Path, dst: &std::path::Path) -> u32 {
                let _ = std::fs::create_dir_all(dst);
                let mut count = 0;
                if let Ok(entries) = std::fs::read_dir(src) {
                    for entry in entries.flatten() {
                        let src_path = entry.path();
                        let dst_path = dst.join(entry.file_name());
                        if src_path.is_dir() {
                            count += copy_dir(&src_path, &dst_path);
                        } else if std::fs::copy(&src_path, &dst_path).is_ok() {
                            count += 1;
                        }
                    }
                }
                count
            }
            let count = copy_dir(
                std::path::Path::new(&self.host_dir),
                std::path::Path::new(dest),
            );
            tracing::info!(
                "[webwright] copied {} files from rootfs to connector workspace: {}",
                count,
                dest
            );
        }
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
            sandbox_dir: "/tmp/webwright/test-123".to_string(),
            host_dir:
                "/home/user/.local/share/pentest-sandbox/blackarch-rootfs/tmp/webwright/test-123"
                    .to_string(),
            connector_dir: Some(
                "/home/user/.local/share/pentest-connector/workspaces/abc/webwright/test-123"
                    .to_string(),
            ),
        };
        assert_eq!(ws.config_path(), "/tmp/webwright/test-123/config.yaml");
        assert_eq!(ws.script_path(), "/tmp/webwright/test-123/script.py");
        assert_eq!(ws.path(), "/tmp/webwright/test-123");
    }
}
