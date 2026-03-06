//! Shared rendering utilities for syntax highlighting, markdown, and file metadata.
//!
//! This module centralises helpers that are used by both the server-rendered
//! file browser (`crate::file_browser`) and the Dioxus UI components
//! (`pentest_ui::components::file_browser`).

use std::sync::LazyLock;

use syntect::highlighting::ThemeSet;
use syntect::html::{css_for_theme_with_class_style, ClassStyle, ClassedHTMLGenerator};
use syntect::parsing::SyntaxSet;
use syntect::util::LinesWithEndings;

// ---------------------------------------------------------------------------
// Syntect statics
// ---------------------------------------------------------------------------

pub static SYNTAX_SET: LazyLock<SyntaxSet> = LazyLock::new(SyntaxSet::load_defaults_newlines);

static SYNTECT_CSS: LazyLock<String> = LazyLock::new(|| {
    let ts = ThemeSet::load_defaults();
    let theme = &ts.themes["base16-ocean.dark"];
    css_for_theme_with_class_style(theme, ClassStyle::Spaced).unwrap_or_default()
});

/// Return the syntect CSS for the `base16-ocean.dark` theme.
pub fn syntect_css() -> &'static str {
    &SYNTECT_CSS
}

// ---------------------------------------------------------------------------
// HTML / text utilities
// ---------------------------------------------------------------------------

/// Escape HTML special characters.
pub fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Format a byte count as a human-readable string.
pub fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

// ---------------------------------------------------------------------------
// Timestamp formatting
// ---------------------------------------------------------------------------

/// Format a `SystemTime` as a `YYYY-MM-DD HH:MM:SS` UTC string.
pub fn format_system_time(time: std::time::SystemTime) -> String {
    let datetime: chrono::DateTime<chrono::Utc> = time.into();
    datetime.format("%Y-%m-%d %H:%M:%S").to_string()
}

// ---------------------------------------------------------------------------
// Syntax highlighting
// ---------------------------------------------------------------------------

/// Detect syntax for a filename, falling back to plain text.
pub fn detect_syntax(filename: &str) -> &syntect::parsing::SyntaxReference {
    SYNTAX_SET
        .find_syntax_for_file(filename)
        .ok()
        .flatten()
        .unwrap_or_else(|| SYNTAX_SET.find_syntax_plain_text())
}

/// Highlight code using syntect with classed spans.
pub fn highlight_code(code: &str, filename: &str) -> String {
    let syntax = detect_syntax(filename);
    let mut generator =
        ClassedHTMLGenerator::new_with_class_style(syntax, &SYNTAX_SET, ClassStyle::Spaced);
    for line in LinesWithEndings::from(code) {
        let _ = generator.parse_html_for_line_which_includes_newline(line);
    }
    generator.finalize()
}

/// Highlight code by language name (for markdown fenced blocks).
pub fn highlight_code_by_lang(code: &str, lang: &str) -> String {
    let syntax = SYNTAX_SET
        .find_syntax_by_token(lang)
        .unwrap_or_else(|| SYNTAX_SET.find_syntax_plain_text());
    let mut generator =
        ClassedHTMLGenerator::new_with_class_style(syntax, &SYNTAX_SET, ClassStyle::Spaced);
    for line in LinesWithEndings::from(code) {
        let _ = generator.parse_html_for_line_which_includes_newline(line);
    }
    generator.finalize()
}

// ---------------------------------------------------------------------------
// File type helpers
// ---------------------------------------------------------------------------

/// Map a filename to a Unicode icon based on extension and type.
pub fn file_icon(name: &str, is_dir: bool) -> &'static str {
    if is_dir {
        return "\u{1F4C1}"; // folder
    }
    let lower = name.to_lowercase();
    if let Some(ext) = lower.rsplit('.').next() {
        match ext {
            "rs" => "\u{1F980}",
            "py" => "\u{1F40D}",
            "md" | "mdx" => "\u{1F4DD}",
            "json" | "toml" | "yaml" | "yml" => "\u{1F4DC}",
            "png" | "jpg" | "jpeg" | "gif" | "svg" | "webp" | "ico" | "bmp" => "\u{1F4F7}",
            "sh" | "bash" | "zsh" => "\u{1F4BB}",
            "zip" | "tar" | "gz" | "bz2" | "xz" | "7z" => "\u{1F4E6}",
            _ => "\u{1F4C4}",
        }
    } else {
        "\u{1F4C4}"
    }
}

/// Return the MIME type for a supported image extension, or `None`.
pub fn image_mime_type(path: &str) -> Option<&'static str> {
    let lower = path.to_lowercase();
    let ext = lower.rsplit('.').next()?;
    match ext {
        "png" => Some("image/png"),
        "jpg" | "jpeg" => Some("image/jpeg"),
        "gif" => Some("image/gif"),
        "svg" => Some("image/svg+xml"),
        "webp" => Some("image/webp"),
        "ico" => Some("image/x-icon"),
        "bmp" => Some("image/bmp"),
        _ => None,
    }
}

/// Check if a path has a markdown extension.
pub fn is_markdown(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower.ends_with(".md") || lower.ends_with(".mdx")
}

// ---------------------------------------------------------------------------
// Markdown rendering
// ---------------------------------------------------------------------------

/// Render markdown to raw HTML (no wrapper div).
///
/// Fenced code blocks are syntax-highlighted via syntect.
pub fn render_markdown_raw(content: &str) -> String {
    use pulldown_cmark::{CodeBlockKind, CowStr, Event, Options, Parser, Tag, TagEnd};

    let options =
        Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH | Options::ENABLE_TASKLISTS;

    let parser = Parser::new_ext(content, options);

    let mut in_code_block = false;
    let mut code_lang = String::new();
    let mut code_buf = String::new();

    let mut events: Vec<Event> = Vec::new();

    for event in parser {
        match event {
            Event::Start(Tag::CodeBlock(CodeBlockKind::Fenced(ref lang))) => {
                in_code_block = true;
                code_lang = lang.to_string();
                code_buf.clear();
                continue;
            }
            Event::End(TagEnd::CodeBlock) if in_code_block => {
                in_code_block = false;
                let highlighted = if code_lang.is_empty() {
                    html_escape(&code_buf)
                } else {
                    highlight_code_by_lang(&code_buf, &code_lang)
                };
                let html = format!(
                    r#"<pre><code class="language-{lang}">{code}</code></pre>"#,
                    lang = html_escape(&code_lang),
                    code = highlighted,
                );
                events.push(Event::Html(CowStr::from(html)));
                continue;
            }
            Event::Text(ref text) if in_code_block => {
                code_buf.push_str(text);
                continue;
            }
            _ => {}
        }
        events.push(event);
    }

    let mut html_output = String::new();
    pulldown_cmark::html::push_html(&mut html_output, events.into_iter());
    html_output
}

/// Render markdown to HTML wrapped in `<div class="markdown-body">...</div>`.
///
/// This is the variant used by the server-rendered file browser.
pub fn render_markdown(content: &str) -> String {
    format!(
        r#"<div class="markdown-body">{}</div>"#,
        render_markdown_raw(content)
    )
}
