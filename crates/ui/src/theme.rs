//! Theme definitions for the pentest connector UI
//!
//! Provides oklch color tokens with WinAMP-style theme support.
//! Token names follow the shadcn/ui convention used by strike48/ui.

use pentest_core::config::{BorderRadius, Density, Theme};

/// Generate CSS custom properties based on theme, border radius, and density settings.
/// Supports WinAMP-style instant theme switching.
pub fn generate_theme_css(theme: Theme, radius: BorderRadius, density: Density) -> String {
    let colors = get_theme_colors(theme);
    let radius_value = get_radius_value(radius);
    let spacing = get_density_spacing(density);

    format!(
        r#"
        :root {{
            /* Theme: {:?} */
            color-scheme: {};

            /* Color tokens */
            --background: {};
            --foreground: {};
            --card: {};
            --popover: {};
            --primary: {};
            --primary-foreground: {};
            --secondary: {};
            --secondary-foreground: {};
            --muted: {};
            --muted-foreground: {};
            --accent: {};
            --accent-foreground: {};
            --destructive: {};
            --border: {};
            --input: {};
            --ring: {};

            /* Shape tokens */
            --radius: {};
            --radius-sm: calc(var(--radius) - 4px);
            --radius-md: calc(var(--radius) - 2px);
            --radius-lg: var(--radius);
            --radius-xl: calc(var(--radius) + 4px);

            /* Spacing tokens (density) */
            --spacing-xs: {};
            --spacing-sm: {};
            --spacing-md: {};
            --spacing-lg: {};
            --spacing-xl: {};

            /* Sidebar tokens */
            --sidebar: {};
            --sidebar-foreground: {};
            --sidebar-primary: {};
            --sidebar-primary-foreground: {};
            --sidebar-accent: {};
            --sidebar-accent-foreground: {};
            --sidebar-border: {};
            --sidebar-ring: {};

            /* Chart tokens */
            --chart-1: {};
            --chart-2: {};
            --chart-3: {};
            --chart-4: {};
            --chart-5: {};

            /* Extended tokens */
            --success: {};
            --warning: {};
            --info: {};

            /* Typography tokens */
            --font-sans: ui-sans-serif, system-ui, sans-serif, 'Apple Color Emoji', 'Segoe UI Emoji', 'Segoe UI Symbol', 'Noto Color Emoji';
            --font-heading: ui-sans-serif, system-ui, sans-serif, 'Apple Color Emoji', 'Segoe UI Emoji', 'Segoe UI Symbol', 'Noto Color Emoji';
            --font-mono: "Cascadia Code", "Fira Code", "Consolas", "Courier New", monospace;
            --font-size: {}px;
        }}
        "#,
        theme,
        colors.color_scheme,
        colors.background,
        colors.foreground,
        colors.card,
        colors.popover,
        colors.primary,
        colors.primary_foreground,
        colors.secondary,
        colors.secondary_foreground,
        colors.muted,
        colors.muted_foreground,
        colors.accent,
        colors.accent_foreground,
        colors.destructive,
        colors.border,
        colors.input,
        colors.ring,
        radius_value,
        spacing.xs,
        spacing.sm,
        spacing.md,
        spacing.lg,
        spacing.xl,
        colors.sidebar,
        colors.sidebar_foreground,
        colors.sidebar_primary,
        colors.sidebar_primary_foreground,
        colors.sidebar_accent,
        colors.sidebar_accent_foreground,
        colors.sidebar_border,
        colors.sidebar_ring,
        colors.chart_1,
        colors.chart_2,
        colors.chart_3,
        colors.chart_4,
        colors.chart_5,
        colors.success,
        colors.warning,
        colors.info,
        spacing.font_size,
    ) + BASE_COMPONENT_STYLES
}

/// Legacy function for backwards compatibility - uses Dark theme defaults
pub fn theme_css() -> &'static str {
    r#"
        :root {
            /* shadcn/ui base tokens - dark mode (default for pentest tool) */
            color-scheme: dark;
            --background: oklch(0.145 0 0);
            --foreground: oklch(0.985 0 0);
            --card: oklch(0.145 0 0);
            --popover: oklch(0.145 0 0);
            --primary: oklch(0.985 0 0);
            --primary-foreground: oklch(0.205 0 0);
            --secondary: oklch(0.269 0 0);
            --secondary-foreground: oklch(0.985 0 0);
            --muted: oklch(0.269 0 0);
            --muted-foreground: oklch(0.708 0 0);
            --accent: oklch(0.269 0 0);
            --accent-foreground: oklch(0.985 0 0);
            --destructive: oklch(0.5058 0.2066 27.85);
            --border: oklch(0.269 0 0);
            --input: oklch(0.269 0 0);
            --ring: oklch(0.439 0 0);
            --radius: 0.625rem;

            /* Sidebar tokens */
            --sidebar: oklch(0.205 0 0);
            --sidebar-foreground: oklch(0.985 0 0);
            --sidebar-primary: oklch(0.488 0.243 264.376);
            --sidebar-primary-foreground: oklch(0.985 0 0);
            --sidebar-accent: oklch(0.269 0 0);
            --sidebar-accent-foreground: oklch(0.985 0 0);
            --sidebar-border: oklch(0.269 0 0);
            --sidebar-ring: oklch(0.439 0 0);

            /* Chart tokens (data visualization) */
            --chart-1: oklch(0.488 0.243 264.376);
            --chart-2: oklch(0.696 0.17 162.48);
            --chart-3: oklch(0.769 0.188 70.08);
            --chart-4: oklch(0.627 0.265 303.9);
            --chart-5: oklch(0.645 0.246 16.439);

            /* Spacing / radius variants */
            --radius-sm: calc(var(--radius) - 4px);
            --radius-md: calc(var(--radius) - 2px);
            --radius-lg: var(--radius);
            --radius-xl: calc(var(--radius) + 4px);

            /* Extended tokens (strike48/ui connector) */
            --success: oklch(0.75 0.18 145);
            --warning: oklch(0.85 0.13 85);
            --info: oklch(0.7 0.15 250);

            /* Typography tokens */
            --font-sans: ui-sans-serif, system-ui, sans-serif, 'Apple Color Emoji', 'Segoe UI Emoji', 'Segoe UI Symbol', 'Noto Color Emoji';
            --font-heading: ui-sans-serif, system-ui, sans-serif, 'Apple Color Emoji', 'Segoe UI Emoji', 'Segoe UI Symbol', 'Noto Color Emoji';
            --font-mono: "Cascadia Code", "Fira Code", "Consolas", "Courier New", monospace;
            --font-size: 14px;
        }

        @media (prefers-color-scheme: light) {
            :root {
                color-scheme: light;
                --background: oklch(1 0 0);
                --foreground: oklch(0.145 0 0);
                --card: oklch(1 0 0);
                --popover: oklch(1 0 0);
                --primary: oklch(0.205 0 0);
                --primary-foreground: oklch(0.985 0 0);
                --secondary: oklch(0.97 0 0);
                --secondary-foreground: oklch(0.205 0 0);
                --muted: oklch(0.97 0 0);
                --muted-foreground: oklch(0.556 0 0);
                --accent: oklch(0.97 0 0);
                --accent-foreground: oklch(0.205 0 0);
                --destructive: oklch(0.5757 0.2352 27.92);
                --border: oklch(0.922 0 0);
                --input: oklch(0.922 0 0);
                --ring: oklch(0.708 0 0);

                /* Sidebar tokens */
                --sidebar: oklch(0.985 0 0);
                --sidebar-foreground: oklch(0.145 0 0);
                --sidebar-primary: oklch(0.205 0 0);
                --sidebar-primary-foreground: oklch(0.985 0 0);
                --sidebar-accent: oklch(0.97 0 0);
                --sidebar-accent-foreground: oklch(0.205 0 0);
                --sidebar-border: oklch(0.922 0 0);
                --sidebar-ring: oklch(0.708 0 0);

                /* Chart tokens (data visualization) */
                --chart-1: oklch(0.646 0.222 41.116);
                --chart-2: oklch(0.6 0.118 184.704);
                --chart-3: oklch(0.398 0.07 227.392);
                --chart-4: oklch(0.828 0.189 84.429);
                --chart-5: oklch(0.769 0.188 70.08);

                --success: oklch(0.55 0.18 145);
                --warning: oklch(0.75 0.15 85);
                --info: oklch(0.6 0.15 250);
            }
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: var(--font-mono);
            font-size: var(--font-size);
            background-color: var(--background);
            color: var(--foreground);
            line-height: 1.5;
        }

        .app-container {
            display: flex;
            flex-direction: column;
            height: 100vh;
            max-height: 100vh;
            overflow: hidden;
        }

        .header {
            padding: 12px 16px;
            background-color: var(--secondary);
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            gap: 16px;
        }

        .main-content {
            flex: 1;
            display: flex;
            flex-direction: column;
            overflow: hidden;
            padding: 16px;
            gap: 16px;
        }

        .terminal {
            flex: 1;
            background-color: var(--secondary);
            border: 1px solid var(--border);
            border-radius: 4px;
            overflow-y: auto;
            overflow-x: hidden;
            padding: 8px 12px;
            font-family: var(--font-mono);
            font-size: 13px;
            scroll-behavior: smooth;
            line-height: 1.5;
        }

        .terminal-line {
            white-space: pre-wrap;
            word-break: break-word;
            padding: 2px 0;
            margin: 1px 0;
        }

        .terminal-line-header.expandable {
            cursor: pointer;
        }

        .terminal-line-header.expandable:hover {
            background-color: color-mix(in srgb, var(--foreground) 5%, transparent);
        }

        .terminal-details {
            margin: 2px 0 4px 20px;
            padding: 6px 10px;
            background-color: color-mix(in srgb, var(--background) 70%, black);
            border-left: 2px solid var(--border);
            border-radius: 0 4px 4px 0;
            font-size: 12px;
            color: var(--muted-foreground);
            white-space: pre-wrap;
            word-break: break-all;
            max-height: 300px;
            overflow-y: auto;
        }

        .terminal-line.debug { color: var(--muted-foreground); }
        .terminal-line.info { color: var(--info); }
        .terminal-line.success { color: var(--success); }
        .terminal-line.warning { color: var(--warning); }
        .terminal-line.error { color: var(--destructive); }

        .status-indicator {
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .status-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            animation: pulse 2s infinite;
        }

        .status-dot.disconnected { background-color: var(--destructive); }
        .status-dot.connecting { background-color: var(--warning); }
        .status-dot.connected { background-color: var(--success); }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        .controls {
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
        }

        .input-group {
            display: flex;
            flex-direction: column;
            gap: 4px;
        }

        .input-group label {
            font-size: 12px;
            color: var(--muted-foreground);
        }

        input, select {
            background-color: var(--background);
            border: 1px solid var(--border);
            border-radius: 4px;
            padding: 8px 12px;
            color: var(--foreground);
            font-family: var(--font-mono);
            font-size: 14px;
        }

        input:focus, select:focus {
            outline: none;
            border-color: var(--primary);
        }

        input[type="password"] {
            letter-spacing: 2px;
        }

        button {
            background-color: var(--primary);
            color: var(--primary-foreground);
            border: none;
            border-radius: 4px;
            padding: 8px 16px;
            font-family: var(--font-mono);
            font-size: 14px;
            cursor: pointer;
            transition: background-color 0.2s;
        }

        button:hover {
            background-color: var(--ring);
        }

        button:disabled {
            background-color: var(--muted-foreground);
            cursor: not-allowed;
        }

        button.danger {
            background-color: var(--destructive);
        }

        button.danger:hover {
            background-color: color-mix(in srgb, var(--destructive) 80%, black);
        }

        button.success {
            background-color: var(--success);
        }

        button.success:hover {
            background-color: color-mix(in srgb, var(--success) 80%, black);
        }

        .config-form {
            background-color: var(--secondary);
            border: 1px solid var(--border);
            border-radius: 4px;
            padding: 16px;
            display: flex;
            flex-direction: column;
            gap: 12px;
        }

        .config-form .form-row {
            display: flex;
            gap: 12px;
        }

        .config-form .input-group {
            flex: 1;
        }

        .progress-bar {
            width: 100%;
            height: 4px;
            background-color: var(--border);
            border-radius: 2px;
            overflow: hidden;
        }

        .progress-bar .fill {
            height: 100%;
            background-color: var(--primary);
            transition: width 0.2s;
        }

        .scan-results {
            max-height: 200px;
            overflow-y: auto;
        }

        .scan-result {
            display: flex;
            gap: 8px;
            padding: 4px 0;
        }

        .scan-result.open { color: var(--success); }
        .scan-result.closed { color: var(--muted-foreground); }

        .header h1 {
            font-size: 16px;
        }
        "#
}

/// Cross-component utility classes (badges, status dots, truncation, etc.).
pub fn utils_css() -> &'static str {
    include_str!("styles/utils.css")
}

/// Responsive / compact CSS layered on top of the base theme.
/// Includes component styles (tab bar, dashboard, etc.) and
/// narrow-viewport overrides that kick in at ≤768px.
pub fn responsive_css() -> &'static str {
    include_str!("styles/mobile.css")
}

/// Alias kept for backwards compatibility.
pub fn mobile_css() -> &'static str {
    responsive_css()
}

/// Generated Tailwind CSS v4 output.
pub fn tailwind_css() -> &'static str {
    include_str!("styles/tailwind-out.css")
}

// ============================================================================
// Theme System - WinAMP-style Theming
// ============================================================================

/// Metadata for a custom theme file
#[derive(Debug, Clone)]
pub struct ThemeMetadata {
    pub name: String,
    pub author: Option<String>,
    pub version: Option<String>,
    pub description: Option<String>,
}

/// A parsed custom theme file with metadata and CSS content
#[derive(Debug, Clone)]
pub struct CustomTheme {
    pub metadata: ThemeMetadata,
    pub css_variables: String,
    pub custom_css: Option<String>,
}

/// Parse a custom theme CSS file with metadata comments
///
/// Format:
/// ```css
/// /* Theme: My Custom Theme */
/// /* Author: John Doe */
/// /* Version: 1.0.0 */
/// /* Description: A beautiful custom theme */
///
/// :root {
///   --background: oklch(0.1 0 0);
///   --foreground: oklch(0.9 0 0);
///   /* ... other variables ... */
/// }
///
/// /* Optional: Custom component styles */
/// .custom-button {
///   border: 2px solid var(--primary);
/// }
/// ```
pub fn parse_theme_file(content: &str) -> Result<CustomTheme, String> {
    // Security: Limit file size to prevent DoS
    const MAX_FILE_SIZE: usize = 100 * 1024; // 100KB
    const MAX_LINE_LENGTH: usize = 1000;

    if content.len() > MAX_FILE_SIZE {
        return Err(format!(
            "Theme file too large: {} bytes (max {}KB)",
            content.len(),
            MAX_FILE_SIZE / 1024
        ));
    }

    let mut metadata = ThemeMetadata {
        name: String::new(),
        author: None,
        version: None,
        description: None,
    };

    let mut css_variables = String::new();
    let mut custom_css = String::new();
    let mut in_root_block = false;
    let mut root_brace_count = 0;

    for line in content.lines() {
        // Security: Limit line length to prevent DoS
        if line.len() > MAX_LINE_LENGTH {
            return Err(format!(
                "Line too long: {} chars (max {})",
                line.len(),
                MAX_LINE_LENGTH
            ));
        }
        let trimmed = line.trim();

        // Parse metadata comments
        if let Some(comment) = trimmed.strip_prefix("/*").and_then(|s| s.strip_suffix("*/")) {
            let comment = comment.trim();
            if let Some(name) = comment.strip_prefix("Theme:") {
                metadata.name = name.trim().to_string();
            } else if let Some(author) = comment.strip_prefix("Author:") {
                metadata.author = Some(author.trim().to_string());
            } else if let Some(version) = comment.strip_prefix("Version:") {
                metadata.version = Some(version.trim().to_string());
            } else if let Some(desc) = comment.strip_prefix("Description:") {
                metadata.description = Some(desc.trim().to_string());
            }
            continue;
        }

        // Track :root { } block
        if trimmed.starts_with(":root") {
            in_root_block = true;
            css_variables.push_str(line);
            css_variables.push('\n');
            continue;
        }

        if in_root_block {
            css_variables.push_str(line);
            css_variables.push('\n');

            // Count braces to detect end of :root block
            root_brace_count += line.matches('{').count() as i32;
            root_brace_count -= line.matches('}').count() as i32;

            if root_brace_count == 0 {
                in_root_block = false;
            }
        } else if !trimmed.is_empty() && !trimmed.starts_with("/*") {
            // Anything outside :root block is custom CSS
            custom_css.push_str(line);
            custom_css.push('\n');
        }
    }

    // Validate required metadata
    if metadata.name.is_empty() {
        return Err("Theme file must include /* Theme: ... */ comment".to_string());
    }

    if css_variables.is_empty() {
        return Err("Theme file must include :root { } block with CSS variables".to_string());
    }

    Ok(CustomTheme {
        metadata,
        css_variables,
        custom_css: if custom_css.trim().is_empty() {
            None
        } else {
            Some(custom_css)
        },
    })
}

/// Validate custom CSS against security blocklist
///
/// Blocks dangerous properties that could:
/// - Execute code (behavior, -moz-binding)
/// - Load external resources (url(), @import)
/// - Inject content (expression())
pub fn validate_custom_css(css: &str) -> Result<(), Vec<String>> {
    let dangerous_patterns = [
        ("javascript:", "JavaScript URLs"),
        ("data:text/html", "HTML data URLs"),
        ("behavior:", "IE behavior property"),
        ("-moz-binding:", "Mozilla XBL bindings"),
        ("expression(", "CSS expressions"),
        ("@import", "CSS imports"),
        ("<script", "Script tags in CSS"),
        ("eval(", "JavaScript eval"),
        ("Function(", "JavaScript Function constructor"),
        ("@font-face", "External font loading"),
        ("@charset", "Charset declarations"),
        ("\\0", "Null byte escapes"),
    ];

    let mut errors = Vec::new();

    for (pattern, description) in &dangerous_patterns {
        if css.to_lowercase().contains(&pattern.to_lowercase()) {
            errors.push(format!("Blocked: {} (found '{}')", description, pattern));
        }
    }

    // Check for url() with non-CSS resources
    if let Some(url_start) = css.find("url(") {
        let url_content = &css[url_start + 4..];
        if let Some(closing) = url_content.find(')') {
            let url_value = url_content[..closing].trim().trim_matches(|c| c == '\'' || c == '"');
            let url_lower = url_value.to_lowercase();

            // Allow data:image/ URLs but block everything else with external protocols
            if url_lower.starts_with("http://")
                || url_lower.starts_with("https://")
                || url_lower.starts_with("ftp://")
                || (url_lower.starts_with("data:") && !url_lower.starts_with("data:image/"))
            {
                errors.push(format!(
                    "Blocked: External resource loading (url({})). Only local paths and data:image/ URLs are allowed.",
                    url_value
                ));
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

#[derive(Debug, Clone)]
struct ThemeColors {
    color_scheme: &'static str,
    background: &'static str,
    foreground: &'static str,
    card: &'static str,
    popover: &'static str,
    primary: &'static str,
    primary_foreground: &'static str,
    secondary: &'static str,
    secondary_foreground: &'static str,
    muted: &'static str,
    muted_foreground: &'static str,
    accent: &'static str,
    accent_foreground: &'static str,
    destructive: &'static str,
    border: &'static str,
    input: &'static str,
    ring: &'static str,
    sidebar: &'static str,
    sidebar_foreground: &'static str,
    sidebar_primary: &'static str,
    sidebar_primary_foreground: &'static str,
    sidebar_accent: &'static str,
    sidebar_accent_foreground: &'static str,
    sidebar_border: &'static str,
    sidebar_ring: &'static str,
    chart_1: &'static str,
    chart_2: &'static str,
    chart_3: &'static str,
    chart_4: &'static str,
    chart_5: &'static str,
    success: &'static str,
    warning: &'static str,
    info: &'static str,
}

#[derive(Debug, Clone)]
struct DensitySpacing {
    xs: &'static str,
    sm: &'static str,
    md: &'static str,
    lg: &'static str,
    xl: &'static str,
    font_size: u32,
}

fn get_theme_colors(theme: Theme) -> ThemeColors {
    match theme {
        Theme::Dark => dark_theme(),
        Theme::Light => light_theme(),
        Theme::Dracula => dracula_theme(),
        Theme::Gruvbox => gruvbox_theme(),
        Theme::TokyoNight => tokyo_night_theme(),
        Theme::Matrix => matrix_theme(),
        Theme::Cyberpunk => cyberpunk_theme(),
        Theme::Nord => nord_theme(),
    }
}

fn get_radius_value(radius: BorderRadius) -> &'static str {
    match radius {
        BorderRadius::Sharp => "0px",
        BorderRadius::Minimal => "4px",
        BorderRadius::Rounded => "8px",
        BorderRadius::Soft => "16px",
        BorderRadius::Pill => "999px",
    }
}

fn get_density_spacing(density: Density) -> DensitySpacing {
    match density {
        Density::Compact => DensitySpacing {
            xs: "2px",
            sm: "4px",
            md: "8px",
            lg: "12px",
            xl: "16px",
            font_size: 12,
        },
        Density::Normal => DensitySpacing {
            xs: "4px",
            sm: "8px",
            md: "12px",
            lg: "16px",
            xl: "24px",
            font_size: 14,
        },
        Density::Comfortable => DensitySpacing {
            xs: "6px",
            sm: "12px",
            md: "16px",
            lg: "24px",
            xl: "32px",
            font_size: 16,
        },
    }
}

// Theme Color Palettes

fn dark_theme() -> ThemeColors {
    ThemeColors {
        color_scheme: "dark",
        background: "oklch(0.145 0 0)",
        foreground: "oklch(0.985 0 0)",
        card: "oklch(0.145 0 0)",
        popover: "oklch(0.145 0 0)",
        primary: "oklch(0.985 0 0)",
        primary_foreground: "oklch(0.205 0 0)",
        secondary: "oklch(0.269 0 0)",
        secondary_foreground: "oklch(0.985 0 0)",
        muted: "oklch(0.269 0 0)",
        muted_foreground: "oklch(0.708 0 0)",
        accent: "oklch(0.269 0 0)",
        accent_foreground: "oklch(0.985 0 0)",
        destructive: "oklch(0.5058 0.2066 27.85)",
        border: "oklch(0.269 0 0)",
        input: "oklch(0.269 0 0)",
        ring: "oklch(0.439 0 0)",
        sidebar: "oklch(0.205 0 0)",
        sidebar_foreground: "oklch(0.985 0 0)",
        sidebar_primary: "oklch(0.488 0.243 264.376)",
        sidebar_primary_foreground: "oklch(0.985 0 0)",
        sidebar_accent: "oklch(0.269 0 0)",
        sidebar_accent_foreground: "oklch(0.985 0 0)",
        sidebar_border: "oklch(0.269 0 0)",
        sidebar_ring: "oklch(0.439 0 0)",
        chart_1: "oklch(0.488 0.243 264.376)",
        chart_2: "oklch(0.696 0.17 162.48)",
        chart_3: "oklch(0.769 0.188 70.08)",
        chart_4: "oklch(0.627 0.265 303.9)",
        chart_5: "oklch(0.645 0.246 16.439)",
        success: "oklch(0.75 0.18 145)",
        warning: "oklch(0.85 0.13 85)",
        info: "oklch(0.7 0.15 250)",
    }
}

fn light_theme() -> ThemeColors {
    ThemeColors {
        color_scheme: "light",
        background: "oklch(1 0 0)",
        foreground: "oklch(0.145 0 0)",
        card: "oklch(1 0 0)",
        popover: "oklch(1 0 0)",
        primary: "oklch(0.205 0 0)",
        primary_foreground: "oklch(0.985 0 0)",
        secondary: "oklch(0.97 0 0)",
        secondary_foreground: "oklch(0.205 0 0)",
        muted: "oklch(0.97 0 0)",
        muted_foreground: "oklch(0.556 0 0)",
        accent: "oklch(0.97 0 0)",
        accent_foreground: "oklch(0.205 0 0)",
        destructive: "oklch(0.5757 0.2352 27.92)",
        border: "oklch(0.922 0 0)",
        input: "oklch(0.922 0 0)",
        ring: "oklch(0.708 0 0)",
        sidebar: "oklch(0.985 0 0)",
        sidebar_foreground: "oklch(0.145 0 0)",
        sidebar_primary: "oklch(0.205 0 0)",
        sidebar_primary_foreground: "oklch(0.985 0 0)",
        sidebar_accent: "oklch(0.97 0 0)",
        sidebar_accent_foreground: "oklch(0.205 0 0)",
        sidebar_border: "oklch(0.922 0 0)",
        sidebar_ring: "oklch(0.708 0 0)",
        chart_1: "oklch(0.646 0.222 41.116)",
        chart_2: "oklch(0.6 0.118 184.704)",
        chart_3: "oklch(0.398 0.07 227.392)",
        chart_4: "oklch(0.828 0.189 84.429)",
        chart_5: "oklch(0.769 0.188 70.08)",
        success: "oklch(0.55 0.18 145)",
        warning: "oklch(0.75 0.15 85)",
        info: "oklch(0.6 0.15 250)",
    }
}

fn dracula_theme() -> ThemeColors {
    ThemeColors {
        color_scheme: "dark",
        background: "oklch(0.053 0.006 260)",    // Near-black #0E0D11
        foreground: "oklch(0.971 0.009 260)",    // Off-white #F8F8F2
        card: "oklch(0.08 0.01 260)",
        popover: "oklch(0.08 0.01 260)",
        primary: "oklch(0.608 0.179 8)",         // Neon pink #FF79C6
        primary_foreground: "oklch(0.971 0.009 260)",
        secondary: "oklch(0.35 0.05 260)",       // Dark purple-gray
        secondary_foreground: "oklch(0.971 0.009 260)",
        muted: "oklch(0.30 0.04 260)",
        muted_foreground: "oklch(0.75 0.05 260)",
        accent: "oklch(0.82 0.15 180)",          // Cyan #8BE9FD
        accent_foreground: "oklch(0.053 0.006 260)",
        destructive: "oklch(0.55 0.22 25)",
        border: "oklch(0.25 0.03 260)",
        input: "oklch(0.15 0.02 260)",
        ring: "oklch(0.608 0.179 8)",
        sidebar: "oklch(0.04 0.005 260)",
        sidebar_foreground: "oklch(0.971 0.009 260)",
        sidebar_primary: "oklch(0.608 0.179 8)",
        sidebar_primary_foreground: "oklch(0.971 0.009 260)",
        sidebar_accent: "oklch(0.35 0.05 260)",
        sidebar_accent_foreground: "oklch(0.971 0.009 260)",
        sidebar_border: "oklch(0.20 0.03 260)",
        sidebar_ring: "oklch(0.608 0.179 8)",
        chart_1: "oklch(0.608 0.179 8)",         // Pink
        chart_2: "oklch(0.78 0.18 145)",         // Green #50FA7B
        chart_3: "oklch(0.82 0.15 180)",         // Cyan
        chart_4: "oklch(0.75 0.20 60)",          // Yellow #F1FA8C
        chart_5: "oklch(0.72 0.18 280)",         // Purple #BD93F9
        success: "oklch(0.78 0.18 145)",
        warning: "oklch(0.80 0.18 70)",
        info: "oklch(0.72 0.18 280)",
    }
}

fn gruvbox_theme() -> ThemeColors {
    ThemeColors {
        color_scheme: "dark",
        background: "oklch(0.157 0.000 260)",    // Dark warm gray #282828
        foreground: "oklch(0.861 0.069 26)",     // Warm beige #ebdbb2
        card: "oklch(0.20 0.01 26)",
        popover: "oklch(0.20 0.01 26)",
        primary: "oklch(0.578 0.256 36)",        // Gruvbox orange #fe8019
        primary_foreground: "oklch(0.157 0.000 260)",
        secondary: "oklch(0.35 0.08 26)",        // Warm dark
        secondary_foreground: "oklch(0.861 0.069 26)",
        muted: "oklch(0.40 0.04 26)",
        muted_foreground: "oklch(0.72 0.06 26)",
        accent: "oklch(0.75 0.18 60)",           // Yellow #fabd2f
        accent_foreground: "oklch(0.157 0.000 260)",
        destructive: "oklch(0.52 0.22 20)",
        border: "oklch(0.35 0.03 26)",
        input: "oklch(0.22 0.02 26)",
        ring: "oklch(0.578 0.256 36)",
        sidebar: "oklch(0.12 0.01 26)",
        sidebar_foreground: "oklch(0.861 0.069 26)",
        sidebar_primary: "oklch(0.578 0.256 36)",
        sidebar_primary_foreground: "oklch(0.157 0.000 260)",
        sidebar_accent: "oklch(0.35 0.08 26)",
        sidebar_accent_foreground: "oklch(0.861 0.069 26)",
        sidebar_border: "oklch(0.30 0.03 26)",
        sidebar_ring: "oklch(0.578 0.256 36)",
        chart_1: "oklch(0.578 0.256 36)",        // Orange
        chart_2: "oklch(0.72 0.15 130)",         // Green #b8bb26
        chart_3: "oklch(0.75 0.18 60)",          // Yellow
        chart_4: "oklch(0.65 0.20 255)",         // Blue #458588
        chart_5: "oklch(0.68 0.16 300)",         // Purple #b16286
        success: "oklch(0.72 0.15 130)",
        warning: "oklch(0.75 0.18 60)",
        info: "oklch(0.65 0.20 255)",
    }
}

fn tokyo_night_theme() -> ThemeColors {
    ThemeColors {
        color_scheme: "dark",
        background: "oklch(0.125 0.020 258)",    // Storm bg #24283b (slightly lighter)
        foreground: "oklch(0.805 0.065 258)",    // Light blue #c0caf5 (brighter)
        card: "oklch(0.16 0.022 258)",
        popover: "oklch(0.16 0.022 258)",
        primary: "oklch(0.645 0.155 254)",       // Tokyo blue #7aa2f7 (brighter)
        primary_foreground: "oklch(0.125 0.020 258)",
        secondary: "oklch(0.32 0.035 258)",      // Dark blue-gray
        secondary_foreground: "oklch(0.805 0.065 258)",
        muted: "oklch(0.38 0.030 258)",
        muted_foreground: "oklch(0.72 0.055 258)",
        accent: "oklch(0.720 0.120 268)",        // Purple #bb9af7 (signature color)
        accent_foreground: "oklch(0.125 0.020 258)",
        destructive: "oklch(0.56 0.22 20)",      // Red #f7768e
        border: "oklch(0.32 0.028 258)",
        input: "oklch(0.20 0.024 258)",
        ring: "oklch(0.645 0.155 254)",
        sidebar: "oklch(0.10 0.018 258)",
        sidebar_foreground: "oklch(0.805 0.065 258)",
        sidebar_primary: "oklch(0.645 0.155 254)",
        sidebar_primary_foreground: "oklch(0.125 0.020 258)",
        sidebar_accent: "oklch(0.32 0.035 258)",
        sidebar_accent_foreground: "oklch(0.805 0.065 258)",
        sidebar_border: "oklch(0.26 0.028 258)",
        sidebar_ring: "oklch(0.645 0.155 254)",
        chart_1: "oklch(0.645 0.155 254)",       // Blue #7aa2f7
        chart_2: "oklch(0.720 0.120 268)",       // Purple #bb9af7
        chart_3: "oklch(0.795 0.145 195)",       // Cyan #7dcfff
        chart_4: "oklch(0.780 0.165 135)",       // Green #9ece6a
        chart_5: "oklch(0.745 0.185 45)",        // Orange #ff9e64
        success: "oklch(0.780 0.165 135)",
        warning: "oklch(0.775 0.175 70)",        // Yellow #e0af68
        info: "oklch(0.645 0.155 254)",
    }
}

fn matrix_theme() -> ThemeColors {
    ThemeColors {
        color_scheme: "dark",
        background: "oklch(0.05 0 0)",          // Pure black
        foreground: "oklch(0.70 0.30 150)",     // Matrix green
        card: "oklch(0.08 0 0)",
        popover: "oklch(0.08 0 0)",
        primary: "oklch(0.70 0.30 150)",        // Phosphor green
        primary_foreground: "oklch(0.05 0 0)",
        secondary: "oklch(0.15 0.10 150)",      // Dark green
        secondary_foreground: "oklch(0.70 0.30 150)",
        muted: "oklch(0.20 0.10 150)",
        muted_foreground: "oklch(0.50 0.20 150)",
        accent: "oklch(0.75 0.35 140)",         // Lime
        accent_foreground: "oklch(0.05 0 0)",
        destructive: "oklch(0.50 0.25 25)",
        border: "oklch(0.20 0.10 150)",
        input: "oklch(0.10 0 0)",
        ring: "oklch(0.60 0.25 150)",
        sidebar: "oklch(0.03 0 0)",
        sidebar_foreground: "oklch(0.70 0.30 150)",
        sidebar_primary: "oklch(0.70 0.30 150)",
        sidebar_primary_foreground: "oklch(0.05 0 0)",
        sidebar_accent: "oklch(0.15 0.10 150)",
        sidebar_accent_foreground: "oklch(0.70 0.30 150)",
        sidebar_border: "oklch(0.15 0.10 150)",
        sidebar_ring: "oklch(0.60 0.25 150)",
        chart_1: "oklch(0.70 0.30 150)",
        chart_2: "oklch(0.75 0.35 140)",
        chart_3: "oklch(0.65 0.25 160)",
        chart_4: "oklch(0.68 0.28 145)",
        chart_5: "oklch(0.72 0.32 155)",
        success: "oklch(0.70 0.30 150)",
        warning: "oklch(0.75 0.30 90)",
        info: "oklch(0.65 0.25 170)",
    }
}

fn cyberpunk_theme() -> ThemeColors {
    ThemeColors {
        color_scheme: "dark",
        background: "oklch(0.06 0.01 300)",     // Very dark, nearly black
        foreground: "oklch(0.95 0.015 300)",    // Clean white (low chroma for readability)
        card: "oklch(0.10 0.02 300)",
        popover: "oklch(0.10 0.02 300)",
        primary: "oklch(0.70 0.35 340)",        // Neon pink (accents only)
        primary_foreground: "oklch(0.95 0.015 300)",
        secondary: "oklch(0.18 0.03 300)",      // Dark purple-gray (readable)
        secondary_foreground: "oklch(0.95 0.015 300)",
        muted: "oklch(0.25 0.03 300)",
        muted_foreground: "oklch(0.70 0.02 300)",
        accent: "oklch(0.75 0.35 180)",         // Bright cyan (accents only)
        accent_foreground: "oklch(0.06 0.01 300)",
        destructive: "oklch(0.55 0.35 25)",
        border: "oklch(0.30 0.25 340)",         // Neon pink border
        input: "oklch(0.12 0.02 300)",
        ring: "oklch(0.70 0.35 340)",           // Neon pink ring
        sidebar: "oklch(0.04 0.01 300)",
        sidebar_foreground: "oklch(0.95 0.015 300)",
        sidebar_primary: "oklch(0.70 0.35 340)",
        sidebar_primary_foreground: "oklch(0.95 0.015 300)",
        sidebar_accent: "oklch(0.18 0.03 300)",
        sidebar_accent_foreground: "oklch(0.95 0.015 300)",
        sidebar_border: "oklch(0.25 0.25 180)", // Neon cyan border
        sidebar_ring: "oklch(0.70 0.35 340)",
        chart_1: "oklch(0.70 0.35 340)",        // Neon pink
        chart_2: "oklch(0.75 0.35 180)",        // Neon cyan
        chart_3: "oklch(0.68 0.32 280)",        // Neon purple
        chart_4: "oklch(0.72 0.35 200)",        // Neon blue
        chart_5: "oklch(0.70 0.33 320)",        // Neon magenta
        success: "oklch(0.70 0.30 160)",
        warning: "oklch(0.80 0.28 80)",
        info: "oklch(0.75 0.35 180)",
    }
}

fn nord_theme() -> ThemeColors {
    ThemeColors {
        color_scheme: "dark",
        background: "oklch(0.265 0.012 220)",   // Nord Polar Night #2e3440 (lighter)
        foreground: "oklch(0.936 0.009 220)",   // Nord Snow Storm #eceff4 (brighter)
        card: "oklch(0.30 0.014 220)",
        popover: "oklch(0.30 0.014 220)",
        primary: "oklch(0.710 0.084 235)",      // Nord Frost #88c0d0 (signature blue)
        primary_foreground: "oklch(0.265 0.012 220)",
        secondary: "oklch(0.42 0.02 220)",      // Lighter secondary
        secondary_foreground: "oklch(0.936 0.009 220)",
        muted: "oklch(0.48 0.015 220)",
        muted_foreground: "oklch(0.78 0.01 220)",
        accent: "oklch(0.640 0.070 230)",       // Nord Frost #5e81ac (frost blue)
        accent_foreground: "oklch(0.936 0.009 220)",
        destructive: "oklch(0.565 0.15 15)",    // Nord Aurora Red #bf616a
        border: "oklch(0.42 0.015 220)",
        input: "oklch(0.35 0.014 220)",
        ring: "oklch(0.710 0.084 235)",
        sidebar: "oklch(0.23 0.012 220)",       // Nord darker #242933
        sidebar_foreground: "oklch(0.936 0.009 220)",
        sidebar_primary: "oklch(0.710 0.084 235)",
        sidebar_primary_foreground: "oklch(0.265 0.012 220)",
        sidebar_accent: "oklch(0.42 0.02 220)",
        sidebar_accent_foreground: "oklch(0.936 0.009 220)",
        sidebar_border: "oklch(0.38 0.015 220)",
        sidebar_ring: "oklch(0.710 0.084 235)",
        chart_1: "oklch(0.710 0.084 235)",      // Frost #88c0d0
        chart_2: "oklch(0.640 0.070 230)",      // Frost #5e81ac
        chart_3: "oklch(0.720 0.095 210)",      // Frost #81a1c1
        chart_4: "oklch(0.770 0.12 155)",       // Aurora Green #a3be8c
        chart_5: "oklch(0.780 0.15 85)",        // Aurora Yellow #ebcb8b
        success: "oklch(0.770 0.12 155)",
        warning: "oklch(0.780 0.15 85)",
        info: "oklch(0.710 0.084 235)",
    }
}

const BASE_COMPONENT_STYLES: &str = r#"
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: var(--font-mono);
            font-size: var(--font-size);
            background-color: var(--background);
            color: var(--foreground);
            line-height: 1.5;
        }

        .app-container {
            display: flex;
            flex-direction: column;
            height: 100vh;
            max-height: 100vh;
            overflow: hidden;
        }

        .header {
            padding: 12px 16px;
            background-color: var(--secondary);
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            gap: 16px;
        }

        .main-content {
            flex: 1;
            display: flex;
            flex-direction: column;
            overflow: hidden;
            padding: 16px;
            gap: 16px;
        }

        .terminal {
            flex: 1;
            background-color: var(--secondary);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            overflow-y: auto;
            overflow-x: hidden;
            padding: 8px 12px;
            font-family: var(--font-mono);
            font-size: 13px;
            scroll-behavior: smooth;
            line-height: 1.5;
        }

        .terminal-line {
            white-space: pre-wrap;
            word-break: break-word;
            padding: 2px 0;
            margin: 1px 0;
        }

        .terminal-line-header.expandable {
            cursor: pointer;
        }

        .terminal-line-header.expandable:hover {
            background-color: color-mix(in srgb, var(--foreground) 5%, transparent);
        }

        .terminal-details {
            margin: 2px 0 4px 20px;
            padding: 6px 10px;
            background-color: color-mix(in srgb, var(--background) 70%, black);
            border-left: 2px solid var(--border);
            border-radius: 0 var(--radius) var(--radius) 0;
            font-size: 12px;
            color: var(--muted-foreground);
            white-space: pre-wrap;
            word-break: break-all;
            max-height: 300px;
            overflow-y: auto;
        }

        .terminal-line.debug { color: var(--muted-foreground); }
        .terminal-line.info { color: var(--info); }
        .terminal-line.success { color: var(--success); }
        .terminal-line.warning { color: var(--warning); }
        .terminal-line.error { color: var(--destructive); }

        .status-indicator {
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .status-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            animation: pulse 2s infinite;
        }

        .status-dot.disconnected { background-color: var(--destructive); }
        .status-dot.connecting { background-color: var(--warning); }
        .status-dot.connected { background-color: var(--success); }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        .controls {
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
        }

        .input-group {
            display: flex;
            flex-direction: column;
            gap: 4px;
        }

        .input-group label {
            font-size: 12px;
            color: var(--muted-foreground);
        }

        input, select {
            background-color: var(--background);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: var(--spacing-sm) var(--spacing-md);
            color: var(--foreground);
            font-family: var(--font-mono);
            font-size: var(--font-size);
        }

        input:focus, select:focus {
            outline: none;
            border-color: var(--primary);
        }

        input[type="password"] {
            letter-spacing: 2px;
        }

        button {
            background-color: var(--primary);
            color: var(--primary-foreground);
            border: none;
            border-radius: var(--radius);
            padding: var(--spacing-sm) var(--spacing-md);
            font-family: var(--font-mono);
            font-size: var(--font-size);
            cursor: pointer;
            transition: background-color 0.2s;
        }

        button:hover {
            background-color: var(--ring);
        }

        button:disabled {
            background-color: var(--muted-foreground);
            cursor: not-allowed;
        }

        button.danger {
            background-color: var(--destructive);
        }

        button.danger:hover {
            background-color: color-mix(in srgb, var(--destructive) 80%, black);
        }

        button.success {
            background-color: var(--success);
        }

        button.success:hover {
            background-color: color-mix(in srgb, var(--success) 80%, black);
        }

        .config-form {
            background-color: var(--secondary);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: var(--spacing-md);
            display: flex;
            flex-direction: column;
            gap: var(--spacing-md);
        }

        .config-form .form-row {
            display: flex;
            gap: var(--spacing-md);
        }

        .config-form .input-group {
            flex: 1;
        }

        .progress-bar {
            width: 100%;
            height: 4px;
            background-color: var(--border);
            border-radius: calc(var(--radius) / 2);
            overflow: hidden;
        }

        .progress-bar .fill {
            height: 100%;
            background-color: var(--primary);
            transition: width 0.2s;
        }

        .scan-results {
            max-height: 200px;
            overflow-y: auto;
        }

        .scan-result {
            display: flex;
            gap: var(--spacing-sm);
            padding: var(--spacing-xs) 0;
        }

        .scan-result.open { color: var(--success); }
        .scan-result.closed { color: var(--muted-foreground); }

        .header h1 {
            font-size: 16px;
        }
        "#;
