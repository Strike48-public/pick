//! CVE database lookup tool

use async_trait::async_trait;
use pentest_core::error::{Error, Result};
use pentest_core::tools::{
    execute_timed, ParamType, PentestTool, Platform, ToolContext, ToolParam, ToolResult, ToolSchema,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::util::param_str;

/// CVE lookup tool
pub struct CveLookupTool;

#[derive(Debug, Serialize, Deserialize)]
struct NvdResponse {
    #[serde(rename = "resultsPerPage")]
    results_per_page: u32,
    #[serde(rename = "totalResults")]
    total_results: u32,
    vulnerabilities: Vec<VulnerabilityWrapper>,
}

#[derive(Debug, Serialize, Deserialize)]
struct VulnerabilityWrapper {
    cve: Cve,
}

#[derive(Debug, Serialize, Deserialize)]
struct Cve {
    id: String,
    descriptions: Vec<Description>,
    #[serde(rename = "publishedDate")]
    published: Option<String>,
    metrics: Option<Metrics>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Description {
    lang: String,
    value: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Metrics {
    #[serde(rename = "cvssMetricV31")]
    cvss_v31: Option<Vec<CvssMetric>>,
    #[serde(rename = "cvssMetricV2")]
    cvss_v2: Option<Vec<CvssMetric>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CvssMetric {
    #[serde(rename = "cvssData")]
    cvss_data: CvssData,
}

#[derive(Debug, Serialize, Deserialize)]
struct CvssData {
    #[serde(rename = "baseSeverity")]
    base_severity: Option<String>,
    #[serde(rename = "baseScore")]
    base_score: f64,
}

impl CveLookupTool {
    /// Query NVD API for CVEs
    async fn query_nvd(product: &str, version: &str) -> Result<Vec<Value>> {
        let client = reqwest::Client::new();

        // Build query parameters
        let mut keyword_query = format!("{} {}", product, version);

        // Normalize product names
        let normalized_product = product.to_lowercase().replace("_", " ");
        if normalized_product != product {
            keyword_query.push_str(&format!(" {}", normalized_product));
        }

        let url = format!(
            "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={}",
            urlencoding::encode(&keyword_query)
        );

        tracing::debug!("Querying NVD API: {}", url);

        // Query NVD API (note: may be rate-limited without API key)
        let response = client
            .get(&url)
            .header("User-Agent", "Pick-PentestTool/1.0")
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| Error::Network(format!("NVD API request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::ToolExecution(format!(
                "NVD API returned error: {}",
                response.status()
            )));
        }

        let nvd_data: NvdResponse = response
            .json()
            .await
            .map_err(|e| Error::ToolExecution(format!("Failed to parse NVD response: {}", e)))?;

        // Convert to simplified format
        let cves: Vec<Value> = nvd_data
            .vulnerabilities
            .into_iter()
            .map(|vuln_wrapper| {
                let cve = vuln_wrapper.cve;

                // Get English description
                let description = cve
                    .descriptions
                    .iter()
                    .find(|d| d.lang == "en")
                    .map(|d| d.value.clone())
                    .unwrap_or_else(|| "No description available".to_string());

                // Get CVSS score and severity
                let (cvss_score, severity) = if let Some(metrics) = &cve.metrics {
                    if let Some(v31) = &metrics.cvss_v31 {
                        if let Some(first) = v31.first() {
                            (
                                first.cvss_data.base_score,
                                first
                                    .cvss_data
                                    .base_severity
                                    .clone()
                                    .unwrap_or_else(|| "UNKNOWN".to_string()),
                            )
                        } else {
                            (0.0, "UNKNOWN".to_string())
                        }
                    } else if let Some(v2) = &metrics.cvss_v2 {
                        if let Some(first) = v2.first() {
                            (
                                first.cvss_data.base_score,
                                Self::cvss_v2_to_severity(first.cvss_data.base_score),
                            )
                        } else {
                            (0.0, "UNKNOWN".to_string())
                        }
                    } else {
                        (0.0, "UNKNOWN".to_string())
                    }
                } else {
                    (0.0, "UNKNOWN".to_string())
                };

                json!({
                    "id": cve.id,
                    "description": description,
                    "cvss": cvss_score,
                    "severity": severity,
                    "published": cve.published,
                })
            })
            .collect();

        Ok(cves)
    }

    /// Convert CVSS v2 score to severity rating
    fn cvss_v2_to_severity(score: f64) -> String {
        if score >= 7.0 {
            "HIGH".to_string()
        } else if score >= 4.0 {
            "MEDIUM".to_string()
        } else {
            "LOW".to_string()
        }
    }
}

#[async_trait]
impl PentestTool for CveLookupTool {
    fn name(&self) -> &str {
        "cve_lookup"
    }

    fn description(&self) -> &str {
        "Look up known CVEs (Common Vulnerabilities and Exposures) for a given product and version"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .param(ToolParam::required(
                "product",
                ParamType::String,
                "Product name (e.g., 'nginx', 'lighttpd', 'openssh')",
            ))
            .param(ToolParam::optional(
                "version",
                ParamType::String,
                "Product version (e.g., '1.18.0')",
                json!(""),
            ))
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![
            Platform::Desktop,
            Platform::Web,
            Platform::Android,
            Platform::Ios,
            Platform::Tui,
        ]
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed(|| async {
            let product = param_str(&params, "product");
            if product.is_empty() {
                return Err(Error::InvalidParams("product parameter is required".into()));
            }

            let version = param_str(&params, "version");

            // Query NVD API
            let cves = Self::query_nvd(&product, &version).await?;

            Ok(json!({
                "product": product,
                "version": if version.is_empty() { Value::Null } else { json!(version) },
                "cves": cves,
                "count": cves.len(),
            }))
        })
        .await
    }
}
