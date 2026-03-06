//! Image viewer component for the file browser.

use dioxus::prelude::*;
use std::path::Path;

use super::read_image;

/// Props for the ImageViewer component
#[derive(Props, Clone, PartialEq)]
pub(super) struct ImageViewerProps {
    /// Path to the workspace directory
    pub workspace_path: String,
    /// Relative path to the image file
    pub rel_path: String,
    /// Called when user clicks back
    pub on_back: EventHandler<()>,
}

/// Image viewer component
#[component]
pub(super) fn ImageViewer(props: ImageViewerProps) -> Element {
    let mut image_data = use_signal(|| None::<(String, String, u64, String)>); // (base64, mime, size, modified)
    let mut error = use_signal(|| None::<String>);
    let mut loading = use_signal(|| true);

    let ws = props.workspace_path.clone();
    let path = props.rel_path.clone();
    let on_back = props.on_back;

    // Load image
    use_effect(move || {
        let ws = ws.clone();
        let path = path.clone();
        spawn(async move {
            loading.set(true);
            match read_image(Path::new(&ws), &path) {
                Ok((bytes, mime, size, modified)) => {
                    use base64::Engine;
                    let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
                    image_data.set(Some((b64, mime, size, modified)));
                    error.set(None);
                }
                Err(e) => {
                    error.set(Some(e));
                }
            }
            loading.set(false);
        });
    });

    let filename = props
        .rel_path
        .rsplit('/')
        .next()
        .unwrap_or(&props.rel_path)
        .to_string();

    rsx! {
        div { class: "image-viewer",
            // Compact toolbar
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
                if let Some((b64, mime, _size, _modified)) = image_data.read().as_ref() {
                    a {
                        class: "copy-btn",
                        href: "data:{mime};base64,{b64}",
                        download: "{filename}",
                        "Download"
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

            // Image -- full bleed
            if let Some((b64, mime, _size, _modified)) = image_data.read().as_ref() {
                div { class: "image-preview",
                    img {
                        src: "data:{mime};base64,{b64}",
                        alt: "{filename}",
                    }
                }
            }
        }
    }
}
