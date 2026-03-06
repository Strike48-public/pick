//! List files tool — lists files and directories in the workspace

use async_trait::async_trait;
use pentest_core::error::Result;
use pentest_core::tools::{
    execute_timed, ParamType, PentestTool, ToolContext, ToolParam, ToolResult, ToolSchema,
};
use pentest_core::workspace;
use serde_json::{json, Value};

/// Tool that lists files and directories in the workspace
pub struct ListFilesTool;

#[async_trait]
impl PentestTool for ListFilesTool {
    fn name(&self) -> &str {
        "list_files"
    }

    fn description(&self) -> &str {
        "List files and directories in the workspace"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description()).param(ToolParam::optional(
            "path",
            ParamType::String,
            "Directory path relative to the workspace (defaults to workspace root)",
            json!("."),
        ))
    }

    async fn execute(&self, params: Value, ctx: &ToolContext) -> Result<ToolResult> {
        let workspace_path = ctx.workspace_path.clone();

        execute_timed(|| async move {
            let workspace = workspace_path.as_ref().ok_or_else(|| {
                pentest_core::error::Error::ToolExecution(
                    "No workspace configured for this session".into(),
                )
            })?;

            let path = params.get("path").and_then(|v| v.as_str()).unwrap_or(".");

            let resolved = workspace::resolve_path(workspace, path)?;

            if !resolved.is_dir() {
                return Err(pentest_core::error::Error::ToolExecution(format!(
                    "Not a directory: {}",
                    path
                )));
            }

            let mut entries = Vec::new();
            let mut read_dir = tokio::fs::read_dir(&resolved).await?;

            while let Ok(Some(entry)) = read_dir.next_entry().await {
                let name = entry.file_name().to_string_lossy().to_string();
                let metadata = entry.metadata().await;
                let (is_dir, size_bytes) = match metadata {
                    Ok(m) => (m.is_dir(), m.len()),
                    Err(_) => (false, 0),
                };
                entries.push(json!({
                    "name": name,
                    "is_dir": is_dir,
                    "size_bytes": size_bytes,
                }));
            }

            Ok(json!({
                "path": path,
                "entries": entries,
                "count": entries.len(),
            }))
        })
        .await
    }
}
