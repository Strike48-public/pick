//! Playbook definitions for toolchain execution

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// Condition for executing a step
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StepCondition {
    /// Always execute
    Always,
    /// Execute if expression evaluates to true (simple key-value checks)
    Expression(String),
}

impl Default for StepCondition {
    fn default() -> Self {
        StepCondition::Always
    }
}

/// A single step in a toolchain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Step {
    /// Unique identifier for this step
    pub id: String,

    /// Tool name to execute
    pub tool: String,

    /// Tool parameters (can include ${variables})
    pub params: HashMap<String, Value>,

    /// Whether this step is required (failure stops execution)
    #[serde(default)]
    pub required: bool,

    /// Condition for executing this step
    #[serde(default)]
    pub condition: StepCondition,

    /// Whether to request user approval before execution
    #[serde(default)]
    pub require_approval: bool,

    /// Risk level for this step
    #[serde(default)]
    pub risk_level: RiskLevel,

    /// Alternative tools to try if this fails
    #[serde(default)]
    pub alternatives: Vec<String>,

    /// Description of what this step does
    pub description: String,
}

/// Risk level for a step
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl Default for RiskLevel {
    fn default() -> Self {
        RiskLevel::Low
    }
}

/// A phase in the attack workflow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Phase {
    /// Phase name
    pub name: String,

    /// Phase description
    pub description: String,

    /// Steps to execute in this phase
    pub steps: Vec<Step>,

    /// Whether to execute steps in parallel
    #[serde(default)]
    pub parallel: bool,
}

/// Tool selection alternatives based on attack profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSelection {
    pub silent: String,
    pub normal: String,
    pub aggressive: String,
}

/// Complete playbook definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Playbook {
    /// Playbook name
    pub name: String,

    /// Playbook description
    pub description: String,

    /// Playbook version
    pub version: String,

    /// Default attack profile
    #[serde(default)]
    pub default_profile: String,

    /// Phases to execute
    pub phases: Vec<Phase>,

    /// Tool selection mappings
    #[serde(default)]
    pub tool_selection: HashMap<String, ToolSelection>,

    /// Success criteria
    #[serde(default)]
    pub success_criteria: Vec<String>,
}

impl Playbook {
    /// Get total number of steps across all phases
    pub fn total_steps(&self) -> usize {
        self.phases.iter().map(|p| p.steps.len()).sum()
    }

    /// Resolve tool name based on attack profile
    pub fn resolve_tool(&self, category: &str, profile: &str) -> Option<String> {
        self.tool_selection.get(category).map(|sel| match profile {
            "silent" => sel.silent.clone(),
            "aggressive" => sel.aggressive.clone(),
            _ => sel.normal.clone(),
        })
    }
}

/// Playbook manager for loading/saving playbooks
pub struct PlaybookManager;

impl PlaybookManager {
    /// Load playbook from YAML string
    pub fn from_yaml(yaml: &str) -> Result<Playbook, String> {
        serde_yaml::from_str(yaml).map_err(|e| format!("Failed to parse YAML: {}", e))
    }

    /// Load playbook from JSON string
    pub fn from_json(json: &str) -> Result<Playbook, String> {
        serde_json::from_str(json).map_err(|e| format!("Failed to parse JSON: {}", e))
    }

    /// Save playbook to YAML string
    pub fn to_yaml(playbook: &Playbook) -> Result<String, String> {
        serde_yaml::to_string(playbook).map_err(|e| format!("Failed to serialize to YAML: {}", e))
    }

    /// Save playbook to JSON string
    pub fn to_json(playbook: &Playbook) -> Result<String, String> {
        serde_json::to_string_pretty(playbook)
            .map_err(|e| format!("Failed to serialize to JSON: {}", e))
    }

    /// Create built-in web app assessment playbook
    pub fn builtin_webapp() -> Playbook {
        Playbook {
            name: "Web Application Assessment".to_string(),
            description: "Comprehensive web application security testing".to_string(),
            version: "1.0".to_string(),
            default_profile: "normal".to_string(),
            phases: vec![
                Phase {
                    name: "Tech Fingerprinting".to_string(),
                    description: "Identify web technologies and WAF".to_string(),
                    parallel: true,
                    steps: vec![
                        Step {
                            id: "whatweb".to_string(),
                            tool: "whatweb".to_string(),
                            params: HashMap::from([(
                                "url".to_string(),
                                Value::String("${target}".to_string()),
                            )]),
                            required: false,
                            condition: StepCondition::Always,
                            require_approval: false,
                            risk_level: RiskLevel::Low,
                            alternatives: vec![],
                            description: "Identify web technologies".to_string(),
                        },
                        Step {
                            id: "wafw00f".to_string(),
                            tool: "wafw00f".to_string(),
                            params: HashMap::from([(
                                "url".to_string(),
                                Value::String("${target}".to_string()),
                            )]),
                            required: false,
                            condition: StepCondition::Always,
                            require_approval: false,
                            risk_level: RiskLevel::Low,
                            alternatives: vec![],
                            description: "Detect Web Application Firewall".to_string(),
                        },
                    ],
                },
                Phase {
                    name: "Content Discovery".to_string(),
                    description: "Discover directories, files, and endpoints".to_string(),
                    parallel: true,
                    steps: vec![
                        Step {
                            id: "gospider".to_string(),
                            tool: "gospider".to_string(),
                            params: HashMap::from([
                                ("url".to_string(), Value::String("${target}".to_string())),
                                ("depth".to_string(), Value::Number(3.into())),
                            ]),
                            required: false,
                            condition: StepCondition::Always,
                            require_approval: false,
                            risk_level: RiskLevel::Low,
                            alternatives: vec!["katana".to_string(), "hakrawler".to_string()],
                            description: "Crawl website for URLs".to_string(),
                        },
                        Step {
                            id: "feroxbuster".to_string(),
                            tool: "feroxbuster".to_string(),
                            params: HashMap::from([
                                ("url".to_string(), Value::String("${target}".to_string())),
                                (
                                    "wordlist".to_string(),
                                    Value::String(
                                        "/usr/share/wordlists/dirb/common.txt".to_string(),
                                    ),
                                ),
                            ]),
                            required: false,
                            condition: StepCondition::Always,
                            require_approval: false,
                            risk_level: RiskLevel::Low,
                            alternatives: vec!["ffuf".to_string(), "gobuster".to_string()],
                            description: "Directory brute-force".to_string(),
                        },
                    ],
                },
                Phase {
                    name: "Parameter Discovery".to_string(),
                    description: "Find input parameters for testing".to_string(),
                    parallel: false,
                    steps: vec![Step {
                        id: "arjun".to_string(),
                        tool: "arjun".to_string(),
                        params: HashMap::from([(
                            "url".to_string(),
                            Value::String("${target}".to_string()),
                        )]),
                        required: false,
                        condition: StepCondition::Always,
                        require_approval: false,
                        risk_level: RiskLevel::Medium,
                        alternatives: vec!["paramspider".to_string()],
                        description: "HTTP parameter discovery".to_string(),
                    }],
                },
                Phase {
                    name: "Vulnerability Scanning".to_string(),
                    description: "Scan for common vulnerabilities".to_string(),
                    parallel: true,
                    steps: vec![
                        Step {
                            id: "nuclei".to_string(),
                            tool: "nuclei".to_string(),
                            params: HashMap::from([
                                ("target".to_string(), Value::String("${target}".to_string())),
                                (
                                    "templates".to_string(),
                                    Value::String("cves,exposures".to_string()),
                                ),
                            ]),
                            required: false,
                            condition: StepCondition::Always,
                            require_approval: false,
                            risk_level: RiskLevel::Medium,
                            alternatives: vec![],
                            description: "Template-based vulnerability scanning".to_string(),
                        },
                        Step {
                            id: "nikto".to_string(),
                            tool: "nikto".to_string(),
                            params: HashMap::from([(
                                "host".to_string(),
                                Value::String("${target}".to_string()),
                            )]),
                            required: false,
                            condition: StepCondition::Always,
                            require_approval: false,
                            risk_level: RiskLevel::Medium,
                            alternatives: vec![],
                            description: "Web server vulnerability scan".to_string(),
                        },
                    ],
                },
                Phase {
                    name: "Exploitation".to_string(),
                    description: "Attempt exploitation of found vulnerabilities".to_string(),
                    parallel: false,
                    steps: vec![
                        Step {
                            id: "sqlmap".to_string(),
                            tool: "sqlmap".to_string(),
                            params: HashMap::from([(
                                "url".to_string(),
                                Value::String("${target}".to_string()),
                            )]),
                            required: false,
                            condition: StepCondition::Always,
                            require_approval: true,
                            risk_level: RiskLevel::High,
                            alternatives: vec![],
                            description: "Automated SQL injection testing".to_string(),
                        },
                        Step {
                            id: "xsstrike".to_string(),
                            tool: "xsstrike".to_string(),
                            params: HashMap::from([(
                                "url".to_string(),
                                Value::String("${target}".to_string()),
                            )]),
                            required: false,
                            condition: StepCondition::Always,
                            require_approval: true,
                            risk_level: RiskLevel::High,
                            alternatives: vec!["dalfox".to_string()],
                            description: "XSS vulnerability testing".to_string(),
                        },
                    ],
                },
            ],
            tool_selection: HashMap::from([(
                "content_discovery".to_string(),
                ToolSelection {
                    silent: "gobuster".to_string(),
                    normal: "feroxbuster".to_string(),
                    aggressive: "ffuf".to_string(),
                },
            )]),
            success_criteria: vec![
                "Identify all accessible endpoints".to_string(),
                "Find at least one exploitable vulnerability".to_string(),
            ],
        }
    }
}
