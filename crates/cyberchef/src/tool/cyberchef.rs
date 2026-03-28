//! CyberChef tool for programmatic recipe execution

use async_trait::async_trait;
use pentest_core::error::{Error, Result};
use pentest_core::tools::{
    execute_timed, ExternalDependency, ParamType, PentestTool, ToolContext, ToolParam, ToolResult,
    ToolSchema,
};
use serde_json::{json, Value};

use super::executor::{ExecutionResult, RecipeExecutor};
use crate::recipes::RecipeLibrary;

/// CyberChef tool for data transformation, encoding, decoding, and analysis
pub struct CyberChefTool {
    executor: RecipeExecutor,
}

impl CyberChefTool {
    pub fn new() -> Self {
        Self {
            executor: RecipeExecutor::new(),
        }
    }
}

impl Default for CyberChefTool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PentestTool for CyberChefTool {
    fn name(&self) -> &str {
        "cyberchef"
    }

    fn description(&self) -> &str {
        "Execute CyberChef recipes for data transformation, encoding, decoding, encryption, and analysis. \
         Supports 20+ pre-built recipes or custom recipe JSON."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .external_dependency(ExternalDependency::new(
                "node",
                "nodejs",
                "Node.js runtime for CyberChef recipe execution (v16 or later)",
            ))
            .param(ToolParam::required(
                "recipe",
                ParamType::String,
                "Recipe name from library (e.g. 'base64_decode', 'jwt_decode') or custom recipe JSON",
            ))
            .param(ToolParam::required(
                "input",
                ParamType::String,
                "Input data to process",
            ))
            .param(ToolParam::optional(
                "input_type",
                ParamType::String,
                "Input format: 'string' (default), 'hex', 'base64'",
                json!("string"),
            ))
            .param(ToolParam::optional(
                "list_recipes",
                ParamType::Boolean,
                "If true, list all available pre-built recipes (ignores other params)",
                json!(false),
            ))
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        // Handle list_recipes flag
        if params
            .get("list_recipes")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            let recipes = RecipeLibrary::list();
            let categories = RecipeLibrary::categories();

            return Ok(ToolResult::success(json!({
                "recipes": recipes.iter().map(|r| json!({
                    "name": r.name,
                    "category": r.category,
                    "description": r.description,
                    "example_input": r.example_input,
                })).collect::<Vec<_>>(),
                "categories": categories,
                "total_count": recipes.len(),
            })));
        }

        execute_timed(|| async move {
            let recipe = params
                .get("recipe")
                .and_then(|v| v.as_str())
                .ok_or_else(|| Error::InvalidParams("recipe parameter is required".into()))?;

            let input = params
                .get("input")
                .and_then(|v| v.as_str())
                .ok_or_else(|| Error::InvalidParams("input parameter is required".into()))?;

            let input_type = params
                .get("input_type")
                .and_then(|v| v.as_str())
                .unwrap_or("string");

            // Determine if recipe is a name or JSON
            let recipe_json = if recipe.starts_with('[') || recipe.starts_with('{') {
                // Custom recipe JSON
                recipe.to_string()
            } else {
                // Pre-built recipe name
                RecipeLibrary::get(recipe).map_err(|e| {
                    Error::InvalidParams(format!("Unknown recipe '{}': {}", recipe, e))
                })?
            };

            // Execute the recipe
            let result: ExecutionResult = self
                .executor
                .execute(&recipe_json, input, input_type)
                .await?;

            Ok(json!({
                "output": result.output,
                "output_type": result.output_type,
                "recipe": recipe,
                "input_length": input.len(),
                "output_length": result.output.len(),
                "execution_time_ms": result.duration_ms,
            }))
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_list_recipes() {
        let tool = CyberChefTool::new();
        let ctx = ToolContext::default();

        let params = json!({
            "list_recipes": true
        });

        let result = tool.execute(params, &ctx).await.unwrap();
        assert!(result.success);

        let recipes = result.data.get("recipes").unwrap().as_array().unwrap();
        assert!(recipes.len() >= 20);
    }

    #[test]
    fn test_schema() {
        let tool = CyberChefTool::new();
        let schema = tool.schema();

        assert_eq!(schema.name, "cyberchef");
        assert!(!schema.description.is_empty());
        assert_eq!(schema.params.len(), 4);
        assert!(!schema.external_dependencies.is_empty());
    }
}
