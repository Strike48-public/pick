//! Theme definitions for the pentest connector UI
//!
//! Provides oklch color tokens with automatic light/dark mode via
//! `prefers-color-scheme`. Token names follow the shadcn/ui convention
//! used by strike48/ui.

/// CSS custom properties (oklch color tokens) with `prefers-color-scheme`
/// light/dark mode support plus base component styles.
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

        /* Light mode disabled — pentest tool always uses dark theme.
           Light mode tokens preserved here for future use if needed.
        */

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
