//! File viewer and code view components for the file browser.

use dioxus::prelude::*;
use std::path::Path;

use pentest_core::rendering::{
    detect_syntax, format_size, highlight_code, is_markdown, render_markdown_raw,
};

use super::{read_file, FileContent};

/// Props for the FileViewer component
#[derive(Props, Clone, PartialEq)]
pub(super) struct FileViewerProps {
    /// Path to the workspace directory
    pub workspace_path: String,
    /// Relative path to the file
    pub rel_path: String,
    /// Called when user clicks back
    pub on_back: EventHandler<()>,
}

/// File viewer component
#[component]
pub(super) fn FileViewer(props: FileViewerProps) -> Element {
    let mut content = use_signal(|| None::<FileContent>);
    let mut error = use_signal(|| None::<String>);
    let mut loading = use_signal(|| true);

    let ws = props.workspace_path.clone();
    let path = props.rel_path.clone();
    let on_back = props.on_back;

    // Load file content
    use_effect(move || {
        let ws = ws.clone();
        let path = path.clone();
        spawn(async move {
            loading.set(true);
            match read_file(Path::new(&ws), &path) {
                Ok(fc) => {
                    content.set(Some(fc));
                    error.set(None);
                }
                Err(e) => {
                    error.set(Some(e));
                }
            }
            loading.set(false);
        });
    });

    let rel_path = props.rel_path.clone();
    let filename = rel_path.rsplit('/').next().unwrap_or(&rel_path).to_string();
    let is_md = is_markdown(&rel_path);

    let syntax_name = detect_syntax(&rel_path).name.clone();

    rsx! {
        div { class: "file-viewer",
            // Compact toolbar: <- filename . type  [Copy]
            div { class: "file-toolbar",
                a {
                    class: "file-toolbar-back",
                    href: "#",
                    onclick: move |e| {
                        e.prevent_default();
                        on_back.call(());
                    },
                    "\u{2190}"
                }
                span { class: "file-toolbar-name", "{filename}" }
                span { class: "file-toolbar-meta", "{syntax_name}" }
                if let Some(fc) = content.read().as_ref() {
                    span { class: "file-toolbar-meta", "{format_size(fc.size)}" }
                    span { class: "file-toolbar-meta", "{fc.modified}" }
                    button {
                        class: "copy-btn",
                        id: "copy-btn",
                        "Copy"
                    }
                }
            }

            // Error
            if let Some(err) = error.read().as_ref() {
                p { class: "error", "{err}" }
            }

            // Loading
            if *loading.read() {
                p { class: "loading", "Loading..." }
            }

            // Content -- full bleed
            if let Some(fc) = content.read().as_ref() {
                if is_md {
                    div {
                        class: "markdown-body",
                        dangerous_inner_html: render_markdown_raw(&fc.content),
                    }
                } else {
                    CodeView {
                        content: fc.content.clone(),
                        filename: rel_path.clone(),
                    }
                }
            }

            // Hidden template for copy functionality
            if let Some(fc) = content.read().as_ref() {
                template {
                    id: "raw-content",
                    "{fc.content}"
                }
            }

            // Copy button script
            script {
                dangerous_inner_html: "(function(){{var btn=document.getElementById('copy-btn');if(btn){{btn.onclick=function(){{var tpl=document.getElementById('raw-content');if(tpl&&navigator.clipboard){{navigator.clipboard.writeText(tpl.innerHTML).then(function(){{btn.textContent='Copied!';setTimeout(function(){{btn.textContent='Copy';}},2000);}});}}}};}}}})()",
            }
        }
    }
}

/// Props for the CodeView component
#[derive(Props, Clone, PartialEq)]
pub(super) struct CodeViewProps {
    /// The file content to display
    pub content: String,
    /// The filename (used for syntax detection)
    pub filename: String,
}

/// Code view with syntax highlighting and line numbers
#[component]
pub(super) fn CodeView(props: CodeViewProps) -> Element {
    let highlighted = highlight_code(&props.content, &props.filename);
    let lines: Vec<&str> = highlighted.lines().collect();

    rsx! {
        div { class: "code-viewer",
            table { class: "code-table",
                tbody {
                    for (i, line) in lines.iter().enumerate() {
                        {
                            let num = i + 1;
                            rsx! {
                                tr { id: "L{num}",
                                    td {
                                        class: "line-number",
                                        "data-line": "{num}",
                                        "{num}"
                                    }
                                    td {
                                        class: "line-content",
                                        dangerous_inner_html: "{line}",
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
