use std::fs;

use strike48_connector::AppPageRequest;

use crate::rendering::{
    file_icon, format_size, highlight_code, html_escape, image_mime_type, is_markdown,
};

use super::fs::{list_directory, read_file};
use super::render::{render_breadcrumbs, render_directory, render_file_view};
use super::*;

/// Create a temporary workspace directory with some test files.
fn setup_workspace() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("create tempdir");
    let root = dir.path();

    // Create files
    fs::write(root.join("hello.txt"), "Hello, world!").unwrap();
    fs::write(root.join("data.json"), r#"{"key": "value"}"#).unwrap();

    // Create a subdirectory with a file
    fs::create_dir(root.join("subdir")).unwrap();
    fs::write(root.join("subdir").join("nested.txt"), "nested content").unwrap();

    dir
}

#[test]
fn test_list_directory_root() {
    let ws = setup_workspace();
    let entries = list_directory(ws.path(), "").unwrap();

    // Should have 3 entries: subdir, data.json, hello.txt
    assert_eq!(entries.len(), 3);

    // Directories come first
    assert!(entries[0].is_dir);
    assert_eq!(entries[0].name, "subdir");

    // Then files alphabetically
    let file_names: Vec<&str> = entries[1..].iter().map(|e| e.name.as_str()).collect();
    assert_eq!(file_names, vec!["data.json", "hello.txt"]);
}

#[test]
fn test_list_directory_subdir() {
    let ws = setup_workspace();
    let entries = list_directory(ws.path(), "subdir").unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "nested.txt");
    assert_eq!(entries[0].path, "subdir/nested.txt");
}

#[test]
fn test_read_file() {
    let ws = setup_workspace();
    let fc = read_file(ws.path(), "hello.txt").unwrap();
    assert_eq!(fc.content, "Hello, world!");
    assert_eq!(fc.line_count, 1);
    assert!(fc.size > 0);
}

#[test]
fn test_read_file_too_large() {
    let ws = setup_workspace();
    // Write a file just over 1 MB
    let big = vec![b'x'; 1_048_577];
    fs::write(ws.path().join("big.bin"), &big).unwrap();
    let err = read_file(ws.path(), "big.bin").unwrap_err().to_string();
    assert!(err.contains("too large"));
}

#[test]
fn test_read_file_binary() {
    let ws = setup_workspace();
    fs::write(ws.path().join("bin.dat"), b"\x00\x01\x02\x03").unwrap();
    let err = read_file(ws.path(), "bin.dat").unwrap_err().to_string();
    assert!(err.contains("binary"));
}

#[test]
fn test_path_traversal_rejected() {
    let ws = setup_workspace();
    let err = list_directory(ws.path(), "../../etc")
        .unwrap_err()
        .to_string();
    assert!(err.contains("denied") || err.contains("escapes") || err.contains("traversal"));
}

#[test]
fn test_handle_request_browse() {
    let ws = setup_workspace();
    let req = AppPageRequest::new("/browse");
    let resp = handle_request(ws.path(), &req);
    assert_eq!(resp.status, 200);
    assert!(resp.body.contains("hello.txt"));
}

#[test]
fn test_handle_request_css() {
    let ws = setup_workspace();
    let req = AppPageRequest::new("/styles.css");
    let resp = handle_request(ws.path(), &req);
    assert_eq!(resp.content_type, "text/css");
    assert!(resp.body.contains("#1e1e1e"));
}

#[test]
fn test_handle_request_404() {
    let ws = setup_workspace();
    let req = AppPageRequest::new("/nonexistent");
    let resp = handle_request(ws.path(), &req);
    assert_eq!(resp.status, 404);
}

#[test]
fn test_html_escape() {
    assert_eq!(
        html_escape("<script>alert('xss')"),
        "&lt;script&gt;alert('xss')"
    );
    assert_eq!(html_escape("a & b"), "a &amp; b");
}

#[test]
fn test_format_size() {
    assert_eq!(format_size(0), "0 B");
    assert_eq!(format_size(512), "512 B");
    assert_eq!(format_size(1024), "1.0 KB");
    assert_eq!(format_size(1_048_576), "1.0 MB");
    assert_eq!(format_size(1_073_741_824), "1.0 GB");
}

#[test]
fn test_file_icon() {
    assert_eq!(file_icon("main.rs", false), "\u{1F980}");
    assert_eq!(file_icon("script.py", false), "\u{1F40D}");
    assert_eq!(file_icon("README.md", false), "\u{1F4DD}");
    assert_eq!(file_icon("data.json", false), "\u{1F4DC}");
    assert_eq!(file_icon("photo.png", false), "\u{1F4F7}");
    assert_eq!(file_icon("run.sh", false), "\u{1F4BB}");
    assert_eq!(file_icon("archive.zip", false), "\u{1F4E6}");
    assert_eq!(file_icon("unknown.xyz", false), "\u{1F4C4}");
    assert_eq!(file_icon("somedir", true), "\u{1F4C1}");
}

#[test]
fn test_is_markdown() {
    assert!(is_markdown("README.md"));
    assert!(is_markdown("doc.MDX"));
    assert!(!is_markdown("code.rs"));
    assert!(!is_markdown("notes.txt"));
}

#[test]
fn test_image_mime_type() {
    assert_eq!(image_mime_type("photo.png"), Some("image/png"));
    assert_eq!(image_mime_type("pic.JPG"), Some("image/jpeg"));
    assert_eq!(image_mime_type("icon.svg"), Some("image/svg+xml"));
    assert_eq!(image_mime_type("code.rs"), None);
}

#[test]
fn test_highlight_code() {
    let code = "fn main() {}";
    let result = highlight_code(code, "test.rs");
    // Should contain span elements from syntect
    assert!(result.contains("<span"));
}

#[test]
fn test_render_breadcrumbs_root() {
    let result = render_breadcrumbs("");
    assert!(result.is_empty());
}

#[test]
fn test_render_breadcrumbs_path() {
    let result = render_breadcrumbs("foo/bar/baz.rs");
    assert!(result.contains("Workspace"));
    assert!(result.contains(r#"<span class="sep">/</span>"#));
    assert!(result.contains("foo"));
    assert!(result.contains("bar"));
    assert!(result.contains("baz.rs"));
}

#[test]
fn test_empty_workspace_message() {
    let html = render_directory("", &[]);
    assert!(html.contains("Workspace is empty"));
    assert!(html.contains("write_file"));
}

#[test]
fn test_empty_subdir_message() {
    let html = render_directory("subdir", &[]);
    assert!(html.contains("This directory is empty."));
    assert!(!html.contains("Workspace is empty"));
}

#[test]
fn test_render_file_view_code() {
    let fc = FileContent {
        content: "fn main() {}\n".to_string(),
        size: 14,
        modified: "2025-01-01 00:00:00".to_string(),
        line_count: 1,
    };
    let html = render_file_view("test.rs", &fc);
    assert!(html.contains("code-viewer"));
    assert!(html.contains("line-number"));
    assert!(html.contains("Back to directory"));
    assert!(html.contains("Copy"));
    assert!(html.contains("Download"));
}

#[test]
fn test_render_file_view_markdown() {
    let fc = FileContent {
        content: "# Hello\n\nWorld\n".to_string(),
        size: 16,
        modified: "2025-01-01 00:00:00".to_string(),
        line_count: 3,
    };
    let html = render_file_view("README.md", &fc);
    assert!(html.contains("markdown-body"));
    assert!(html.contains("<h1>"));
    assert!(html.contains("Raw"));
}

#[test]
fn test_handle_request_raw() {
    let ws = setup_workspace();
    fs::write(ws.path().join("test.md"), "# Title\n\nContent").unwrap();
    let req = AppPageRequest::new("/raw").param("path", "test.md");
    let resp = handle_request(ws.path(), &req);
    assert_eq!(resp.status, 200);
    assert!(resp.body.contains("code-viewer"));
}
