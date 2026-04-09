//! Directory listing component for the file browser.

use dioxus::prelude::*;
use std::path::Path;

use pentest_core::rendering::{file_icon, format_size};

use super::{list_directory, FileEntry};

/// Props for the DirectoryListing component
#[derive(Props, Clone, PartialEq)]
pub(super) struct DirectoryListingProps {
    /// Path to the workspace directory
    pub workspace_path: String,
    /// Relative path within the workspace
    pub rel_path: String,
    /// Called when user clicks an entry
    pub on_navigate: EventHandler<FileEntry>,
}

/// Directory listing component
#[component]
pub(super) fn DirectoryListing(props: DirectoryListingProps) -> Element {
    let mut entries = use_signal(Vec::<FileEntry>::new);
    let mut error = use_signal(|| None::<String>);
    let mut loading = use_signal(|| true);

    let ws = props.workspace_path.clone();
    let path = props.rel_path.clone();
    let on_navigate = props.on_navigate;

    // Load directory contents and poll for changes every 2 seconds
    {
        let ws = ws.clone();
        let path = path.clone();
        use_future(move || {
            let ws = ws.clone();
            let path = path.clone();
            async move {
                loop {
                    match list_directory(Path::new(&ws), &path) {
                        Ok(e) => {
                            entries.set(e);
                            error.set(None);
                        }
                        Err(e) => {
                            error.set(Some(e));
                        }
                    }
                    loading.set(false);
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
            }
        });
    }

    // Parent directory link
    let rel_path = props.rel_path.clone();
    let parent_path = if rel_path.is_empty() {
        None
    } else {
        Some(
            rel_path
                .rsplit_once('/')
                .map(|(p, _)| p.to_string())
                .unwrap_or_default(),
        )
    };

    rsx! {
        div { class: "directory-listing",
            // Parent link
            if let Some(parent) = parent_path {
                a {
                    class: "parent-link",
                    href: "#",
                    onclick: move |e| {
                        e.prevent_default();
                        on_navigate.call(FileEntry {
                            name: "..".to_string(),
                            path: parent.clone(),
                            is_dir: true,
                            size: 0,
                            modified: String::new(),
                        });
                    },
                    "\u{2190} Parent directory"
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

            // Empty state
            if !*loading.read() && entries.read().is_empty() && error.read().is_none() {
                if rel_path.is_empty() {
                    div { class: "empty-workspace",
                        div { class: "empty-icon", "\u{1F4C1}" }
                        p { class: "empty-title", "Workspace is empty" }
                        p { class: "empty-hint",
                            "Files will appear here when created via the "
                            code { "write_file" }
                            " or "
                            code { "screenshot" }
                            " tools."
                        }
                    }
                } else {
                    p { class: "empty", "This directory is empty." }
                }
            }

            // Table
            if !entries.read().is_empty() {
                table {
                    thead {
                        tr {
                            th { "Name" }
                            th { "Size" }
                            th { "Modified" }
                        }
                    }
                    tbody {
                        for entry in entries.read().iter() {
                            {
                                let entry_clone = entry.clone();
                                let icon = file_icon(&entry.name, entry.is_dir);
                                let size = if entry.is_dir { "-".to_string() } else { format_size(entry.size) };
                                rsx! {
                                    tr {
                                        onclick: move |_| {
                                            on_navigate.call(entry_clone.clone());
                                        },
                                        td {
                                            span { class: "icon", "{icon}" }
                                            span { class: "name", "{entry.name}" }
                                        }
                                        td { class: "size", "{size}" }
                                        td { class: "date", "{entry.modified}" }
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
