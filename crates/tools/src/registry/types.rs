//! Types for quick actions

/// A quick action that can be triggered from the UI
#[derive(Debug, Clone)]
pub struct QuickAction {
    /// Unique identifier for this action
    pub id: String,
    /// Display label (e.g., "Detailed Scan")
    pub label: String,
    /// Description text (e.g., "Show client counts (~30s)")
    pub description: String,
    /// Icon to display
    pub icon: TablerIcon,
    /// Visual style/color
    pub style: ActionStyle,
    /// Prompt to send to the agent when clicked
    pub prompt: String,
}

/// Visual style for action buttons
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionStyle {
    /// Main next step action (blue)
    Primary,
    /// Optional/informational action (gray)
    Secondary,
    /// Exploit/attack action (red)
    Danger,
    /// Save/export action (green)
    Info,
}

/// Tabler icon with emoji fallback
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TablerIcon {
    /// Scan icon
    Scan,
    /// Shield icon
    Shield,
    /// Terminal icon
    Terminal,
    /// Network icon
    Network,
    /// WiFi icon
    Wifi,
    /// Bug icon
    Bug,
    /// Database icon
    Database,
    /// Lock icon
    Lock,
    /// Key icon
    Key,
    /// Search icon
    Search,
    /// Bolt/lightning icon
    Bolt,
    /// Target icon
    Target,
    /// File report icon
    FileReport,
    /// Globe/world icon
    World,
    /// Radar icon
    Radar,
    /// Code icon
    Code,
    /// Alert triangle icon
    AlertTriangle,
    /// Custom icon (emoji fallback)
    Custom(String),
}

impl TablerIcon {
    /// Get the Tabler CSS class for this icon
    pub fn to_class(&self) -> String {
        let icon_name = match self {
            TablerIcon::Scan => "scan",
            TablerIcon::Shield => "shield",
            TablerIcon::Terminal => "terminal",
            TablerIcon::Network => "network",
            TablerIcon::Wifi => "wifi",
            TablerIcon::Bug => "bug",
            TablerIcon::Database => "database",
            TablerIcon::Lock => "lock",
            TablerIcon::Key => "key",
            TablerIcon::Search => "search",
            TablerIcon::Bolt => "bolt",
            TablerIcon::Target => "target",
            TablerIcon::FileReport => "file-report",
            TablerIcon::World => "world",
            TablerIcon::Radar => "radar",
            TablerIcon::Code => "code",
            TablerIcon::AlertTriangle => "alert-triangle",
            TablerIcon::Custom(_) => return String::new(),
        };
        format!("ti ti-{}", icon_name)
    }

    /// Get emoji fallback for this icon
    pub fn emoji_fallback(&self) -> &str {
        match self {
            TablerIcon::Scan => "🔍",
            TablerIcon::Shield => "🛡️",
            TablerIcon::Terminal => "💻",
            TablerIcon::Network => "🌐",
            TablerIcon::Wifi => "📡",
            TablerIcon::Bug => "🐛",
            TablerIcon::Database => "🗄️",
            TablerIcon::Lock => "🔒",
            TablerIcon::Key => "🔑",
            TablerIcon::Search => "🔎",
            TablerIcon::Bolt => "⚡",
            TablerIcon::Target => "🎯",
            TablerIcon::FileReport => "📄",
            TablerIcon::World => "🌍",
            TablerIcon::Radar => "📡",
            TablerIcon::Code => "💾",
            TablerIcon::AlertTriangle => "⚠️",
            TablerIcon::Custom(emoji) => emoji.as_str(),
        }
    }
}
