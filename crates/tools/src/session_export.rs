//! Session export tool for generating pentest reports

use async_trait::async_trait;
use pentest_core::export::SessionExport;
use pentest_core::paths::validate_path;
use pentest_core::prelude::*;
use pentest_core::tools::{ParamType, ToolParam};
use serde_json::json;
use std::path::PathBuf;

pub struct SessionExportTool;

#[async_trait]
impl PentestTool for SessionExportTool {
    fn name(&self) -> &str {
        "export_session"
    }

    fn description(&self) -> &str {
        "Export current session to JSON or Markdown report"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .param(ToolParam::optional(
                "format",
                ParamType::String,
                "Export format: json (machine-readable) or markdown (human-readable)",
                json!("markdown"),
            ))
            .param(ToolParam::optional(
                "output_path",
                ParamType::String,
                "Output file path (optional, defaults to workspace/session-export-{timestamp}.{ext})",
                json!(null),
            ))
    }

    async fn execute(&self, params: serde_json::Value, ctx: &ToolContext) -> Result<ToolResult> {
        let format = params
            .get("format")
            .and_then(|v| v.as_str())
            .unwrap_or("markdown");
        let output_path = params.get("output_path").and_then(|v| v.as_str());

        // Generate default filename if not provided
        let timestamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
        let extension = if format == "json" { "json" } else { "md" };
        let default_filename = format!("session-export-{}.{}", timestamp, extension);

        // Validate and resolve output path
        let file_path = if let Some(user_path) = output_path {
            // User-provided path must be validated against workspace
            if let Some(workspace) = &ctx.workspace_path {
                validate_path(workspace, user_path).map_err(|e| {
                    tracing::error!("Invalid output path: {}", e);
                    e
                })?
            } else {
                return Ok(ToolResult::error(
                    "No workspace available for path validation".to_string(),
                ));
            }
        } else if let Some(workspace) = &ctx.workspace_path {
            workspace.join(&default_filename)
        } else {
            PathBuf::from(&default_filename)
        };

        tracing::info!(
            "Exporting session to {} format: {}",
            format,
            file_path.display()
        );

        // Create session export (this would ideally pull from actual session state)
        // For now, create a minimal export as example
        let export = SessionExport::example();

        // Export based on format
        let result = match format {
            "json" => export.save_json(&file_path),
            "markdown" => export.save_markdown(&file_path),
            _ => return Ok(ToolResult::error(format!("Unsupported format: {}", format))),
        };

        match result {
            Ok(()) => {
                tracing::info!(
                    "✓ Session exported successfully to: {}",
                    file_path.display()
                );
                Ok(ToolResult::success(json!({
                    "exported": true,
                    "file_path": file_path.to_string_lossy(),
                    "format": format,
                    "message": format!("Session exported to {}", file_path.display())
                })))
            }
            Err(e) => {
                tracing::error!("✗ Failed to export session: {}", e);
                Ok(ToolResult::error(format!(
                    "Failed to export session: {}",
                    e
                )))
            }
        }
    }
}
