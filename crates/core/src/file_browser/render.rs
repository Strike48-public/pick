//! HTML rendering and route handlers for the file browser.

use std::path::Path;

use base64::Engine;

use strike48_connector::AppPageResponse;

use crate::rendering::{
    detect_syntax, file_icon, format_size, format_system_time, highlight_code, html_escape,
    image_mime_type, is_markdown, render_markdown, syntect_css,
};

use super::fs::{list_directory, read_file};
use super::{FileContent, FileEntry};

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

pub(super) fn handle_browse(workspace: &Path, rel_path: &str) -> AppPageResponse {
    match list_directory(workspace, rel_path) {
        Ok(entries) => {
            let content = render_directory(rel_path, &entries);
            let title = if rel_path.is_empty() {
                "Workspace Files".to_string()
            } else {
                format!("/{}", rel_path)
            };
            AppPageResponse::html(layout(&title, rel_path, &content))
        }
        Err(e) => AppPageResponse::error(400, html_escape(&e.to_string())),
    }
}

pub(super) fn handle_view(workspace: &Path, rel_path: &str) -> AppPageResponse {
    // bd-34: Check for image files BEFORE read_file (which rejects binary)
    if let Some(mime) = image_mime_type(rel_path) {
        return handle_view_image(workspace, rel_path, mime);
    }

    match read_file(workspace, rel_path) {
        Ok(fc) => {
            let rendered = render_file_view(rel_path, &fc);
            let title = rel_path.rsplit('/').next().unwrap_or(rel_path);
            AppPageResponse::html(layout(title, rel_path, &rendered))
        }
        Err(e) => AppPageResponse::error(400, html_escape(&e.to_string())),
    }
}

/// Serve markdown source as plain pre/code (bd-32 /raw route).
pub(super) fn handle_raw(workspace: &Path, rel_path: &str) -> AppPageResponse {
    match read_file(workspace, rel_path) {
        Ok(fc) => {
            let parent = rel_path.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
            let filename = rel_path.rsplit('/').next().unwrap_or(rel_path);
            let header = render_file_header(rel_path, &fc);
            let code = render_code_with_lines(rel_path, &fc.content);
            let raw_template = render_raw_content_template(&fc.content);
            let back_link = format!(
                r#"<a class="parent-link" href="/view?path={}">&larr; Back to rendered view</a>"#,
                html_escape(rel_path),
            );
            let bottom_nav = format!(
                r#"<div class="bottom-nav"><a href="/browse?path={}">&larr; Back to directory</a></div>"#,
                html_escape(parent),
            );
            let rendered = format!(
                r#"<a class="parent-link" href="/browse?path={parent}">&larr; Back to directory</a>
{header}
{code}
{raw_template}
{back_link}
{bottom_nav}"#,
                parent = html_escape(parent),
                header = header,
                code = code,
                raw_template = raw_template,
                back_link = back_link,
                bottom_nav = bottom_nav,
            );
            let title = format!("{} (raw)", filename);
            AppPageResponse::html(layout(&title, rel_path, &rendered))
        }
        Err(e) => AppPageResponse::error(400, html_escape(&e.to_string())),
    }
}

/// Handle image file viewing (bd-34).
fn handle_view_image(workspace: &Path, rel_path: &str, mime: &str) -> AppPageResponse {
    if rel_path.is_empty() {
        return AppPageResponse::error(400, "No file path specified".to_string());
    }

    let target = match crate::workspace::resolve_path(workspace, rel_path) {
        Ok(p) => p,
        Err(e) => return AppPageResponse::error(400, format!("Access denied: {}", e)),
    };

    let meta = match std::fs::metadata(&target) {
        Ok(m) => m,
        Err(e) => return AppPageResponse::error(400, format!("Cannot stat file: {}", e)),
    };

    const MAX_IMAGE_SIZE: u64 = 10_485_760; // 10 MB
    if meta.len() > MAX_IMAGE_SIZE {
        return AppPageResponse::error(
            400,
            format!(
                "Image too large ({}) — limit is 10 MB",
                format_size(meta.len())
            ),
        );
    }

    let bytes = match std::fs::read(&target) {
        Ok(b) => b,
        Err(e) => return AppPageResponse::error(400, format!("Cannot read file: {}", e)),
    };

    let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
    let parent = rel_path.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
    let filename = rel_path.rsplit('/').next().unwrap_or(rel_path);

    let modified = meta
        .modified()
        .ok()
        .map(format_system_time)
        .unwrap_or_else(|| "-".to_string());

    let content = format!(
        r#"<a class="parent-link" href="/browse?path={parent}">&larr; Back to directory</a>
<div class="file-header">
    <div class="file-header-left">
        <span class="file-header-name">{filename}</span>
        <span class="file-header-meta">{mime}</span>
        <span class="file-header-meta">{size}</span>
        <span class="file-header-meta">{modified}</span>
    </div>
    <div class="file-header-right">
        <a href="data:{mime};base64,{b64}" download="{filename}">Download</a>
    </div>
</div>
<div class="image-preview">
    <img src="data:{mime};base64,{b64}" alt="{filename}">
</div>
<div class="bottom-nav"><a href="/browse?path={parent}">&larr; Back to directory</a></div>"#,
        parent = html_escape(parent),
        filename = html_escape(filename),
        mime = mime,
        size = format_size(meta.len()),
        modified = html_escape(&modified),
        b64 = b64,
    );

    let title = rel_path.rsplit('/').next().unwrap_or(rel_path);
    AppPageResponse::html(layout(title, rel_path, &content))
}

// ---------------------------------------------------------------------------
// HTML rendering
// ---------------------------------------------------------------------------

/// Wrap page content in the HTML layout shell.
pub(super) fn layout(title: &str, breadcrumb_path: &str, content: &str) -> String {
    let breadcrumbs = render_breadcrumbs(breadcrumb_path);
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} — Workspace Files</title>
<link rel="stylesheet" href="/styles.css">
</head>
<body style="background:#1e1e1e;color:#e0e0e0">
<div id="turbo-bar" class="turbo-bar"></div>
<header>
<h1><a href="/browse">Workspace Files</a></h1>
{breadcrumbs}
</header>
<main>
{content}
</main>
{scripts}
</body>
</html>"#,
        title = html_escape(title),
        breadcrumbs = breadcrumbs,
        content = content,
        scripts = turbo_scripts(),
    )
}

/// Render breadcrumb navigation from a relative path (bd-28: root shows "Workspace").
pub(super) fn render_breadcrumbs(rel_path: &str) -> String {
    if rel_path.is_empty() {
        return String::new();
    }

    let mut crumbs = vec![r#"<a href="/browse">Workspace</a>"#.to_string()];
    let parts: Vec<&str> = rel_path.split('/').filter(|s| !s.is_empty()).collect();

    for (i, part) in parts.iter().enumerate() {
        let partial: String = parts[..=i].join("/");
        crumbs.push(format!(
            r#"<a href="/browse?path={path}">{name}</a>"#,
            path = html_escape(&partial),
            name = html_escape(part),
        ));
    }

    format!(
        r#"<nav class="breadcrumbs">{}</nav>"#,
        crumbs.join(r#" <span class="sep">/</span> "#)
    )
}

/// Render a directory listing as an HTML table.
pub(super) fn render_directory(rel_path: &str, entries: &[FileEntry]) -> String {
    let mut html = String::new();

    // Parent directory link
    if !rel_path.is_empty() {
        let parent = rel_path.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
        html.push_str(&format!(
            r#"<a class="parent-link" href="/browse?path={}">&larr; Parent directory</a>"#,
            html_escape(parent),
        ));
    }

    if entries.is_empty() {
        if rel_path.is_empty() {
            // bd-28: Empty workspace root — onboarding message
            html.push_str(
                r#"<div class="empty-workspace">
<div class="empty-icon">&#128193;</div>
<p class="empty-title">Workspace is empty</p>
<p class="empty-hint">Files will appear here when created via the <code>write_file</code> or <code>screenshot</code> tools.</p>
</div>"#,
            );
        } else {
            html.push_str(r#"<p class="empty">This directory is empty.</p>"#);
        }
        return html;
    }

    html.push_str(
        r#"<table>
<thead><tr><th>Name</th><th>Size</th><th>Modified</th></tr></thead>
<tbody>
"#,
    );

    for entry in entries {
        let icon = file_icon(&entry.name, entry.is_dir);
        let link = if entry.is_dir {
            format!(
                r#"<a href="/browse?path={}">{} {}</a>"#,
                html_escape(&entry.path),
                icon,
                html_escape(&entry.name),
            )
        } else {
            format!(
                r#"<a href="/view?path={}">{} {}</a>"#,
                html_escape(&entry.path),
                icon,
                html_escape(&entry.name),
            )
        };

        let size = if entry.is_dir {
            "-".to_string()
        } else {
            format_size(entry.size)
        };

        html.push_str(&format!(
            "<tr><td>{link}</td><td class=\"size\">{size}</td><td class=\"date\">{modified}</td></tr>\n",
            link = link,
            size = size,
            modified = html_escape(&entry.modified),
        ));
    }

    html.push_str("</tbody>\n</table>");
    html
}

/// Render the file metadata header bar (bd-32).
pub(super) fn render_file_header(rel_path: &str, fc: &FileContent) -> String {
    let filename = rel_path.rsplit('/').next().unwrap_or(rel_path);
    let syntax = detect_syntax(rel_path);
    let lang_label = syntax.name.as_str();

    let raw_link = if is_markdown(rel_path) {
        format!(r#"<a href="/raw?path={}">Raw</a>"#, html_escape(rel_path),)
    } else {
        String::new()
    };

    let download_data = base64::engine::general_purpose::STANDARD.encode(fc.content.as_bytes());
    let download_link = format!(
        r#"<a href="data:text/plain;base64,{data}" download="{filename}">Download</a>"#,
        data = download_data,
        filename = html_escape(filename),
    );

    let copy_button = r#"<button class="copy-btn" onclick="copyFileContent()" title="Copy to clipboard">Copy</button>"#;

    format!(
        r#"<div class="file-header">
    <div class="file-header-left">
        <span class="file-header-name">{filename}</span>
        <span class="file-header-meta">{lang}</span>
        <span class="file-header-meta">{lines} lines</span>
        <span class="file-header-meta">{size}</span>
        <span class="file-header-meta">{modified}</span>
    </div>
    <div class="file-header-right">
        {copy_button}
        {raw_link}
        {download_link}
    </div>
</div>"#,
        filename = html_escape(filename),
        lang = html_escape(lang_label),
        lines = fc.line_count,
        size = format_size(fc.size),
        modified = html_escape(&fc.modified),
        copy_button = copy_button,
        raw_link = raw_link,
        download_link = download_link,
    )
}

/// Render highlighted code with line numbers in a table (bd-31).
pub(super) fn render_code_with_lines(filename: &str, content: &str) -> String {
    let highlighted = highlight_code(content, filename);
    let mut rows = String::new();

    for (i, line) in highlighted.lines().enumerate() {
        let num = i + 1;
        rows.push_str(&format!(
            r#"<tr id="L{num}"><td class="line-number" data-line="{num}">{num}</td><td class="line-content">{line}</td></tr>
"#,
            num = num,
            line = line,
        ));
    }

    // Handle empty file
    if rows.is_empty() {
        rows.push_str(
            r#"<tr id="L1"><td class="line-number" data-line="1">1</td><td class="line-content"></td></tr>
"#,
        );
    }

    format!(
        r#"<div class="code-viewer"><table class="code-table"><tbody>
{rows}</tbody></table></div>"#,
        rows = rows,
    )
}

/// Hidden template element with raw content for the copy button (bd-35).
pub(super) fn render_raw_content_template(content: &str) -> String {
    format!(
        r#"<template id="raw-content">{}</template>"#,
        html_escape(content),
    )
}

/// Render a file's content in a code viewer (bd-30/31/32/33/35).
pub(super) fn render_file_view(rel_path: &str, fc: &FileContent) -> String {
    let parent = rel_path.rsplit_once('/').map(|(p, _)| p).unwrap_or("");

    let header = render_file_header(rel_path, fc);
    let raw_template = render_raw_content_template(&fc.content);

    let body = if is_markdown(rel_path) {
        render_markdown(&fc.content)
    } else {
        render_code_with_lines(rel_path, &fc.content)
    };

    let bottom_nav = format!(
        r#"<div class="bottom-nav"><a href="/browse?path={}">&larr; Back to directory</a></div>"#,
        html_escape(parent),
    );

    format!(
        r#"<a class="parent-link" href="/browse?path={parent}">&larr; Back to directory</a>
{header}
{body}
{raw_template}
{bottom_nav}"#,
        parent = html_escape(parent),
        header = header,
        body = body,
        raw_template = raw_template,
        bottom_nav = bottom_nav,
    )
}

/// All inline scripts: turbo-nav + line highlighting + copy button.
fn turbo_scripts() -> String {
    format!(
        "<script>{}</script>",
        include_str!("../assets/turbo_nav.js")
    )
}

// ---------------------------------------------------------------------------
// CSS (bd-27: aligned to theme.rs DARK_THEME)
// ---------------------------------------------------------------------------

/// Dark-theme CSS for the file browser.
pub(super) fn file_browser_css() -> String {
    let mut css = include_str!("../assets/file_browser.css").to_string();
    // Append syntect theme CSS
    css.push_str(syntect_css());
    css
}
