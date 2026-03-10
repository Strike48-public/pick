//! Settings page — Connection, Downloads, and Shell Mode controls
//! with form change tracking (original/discard pattern).

use dioxus::prelude::*;
use pentest_core::config::ShellMode;

use super::icons::{Download, Settings, Wifi};

#[component]
pub fn SettingsPage(
    #[props(default = true)] show_connection: bool,
    #[props(default)] connected: bool,
    #[props(default)] host: String,
    #[props(default)] on_disconnect: EventHandler<()>,
    blackarch_downloaded: bool,
    download_progress: Option<f64>,
    on_start_download: EventHandler<()>,
    #[props(default)] setup_error: Option<String>,
    shell_mode: ShellMode,
    on_shell_mode_change: EventHandler<ShellMode>,
) -> Element {
    // -----------------------------------------------------------------------
    // Auto-save on toggle with visual feedback
    // -----------------------------------------------------------------------

    let is_proot = shell_mode == ShellMode::Proot;

    // Track which mode was just saved for visual feedback (bold border)
    let mut just_saved = use_signal(|| None::<ShellMode>);

    // Handler: toggle and auto-save
    let mut on_toggle = {
        let on_shell_mode_change = on_shell_mode_change;
        move |mode: ShellMode| {
            on_shell_mode_change.call(mode);
            // Show saved feedback
            just_saved.set(Some(mode));
            // Auto-hide after 2 seconds
            spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                just_saved.set(None);
            });
        }
    };

    rsx! {
        style { {include_str!("css/settings_page.css")} }

        div { class: "settings-page",
            div { class: "settings-body",

            // Connection card (hidden in workspace app)
            if show_connection {
                div { class: "settings-card dashboard-card",
                    div { class: "settings-card-header",
                        span { class: "settings-card-icon", Wifi { size: 16 } }
                        h2 { "Connection" }
                    }
                    div { class: "settings-card-body",
                        if connected {
                            div { class: "sidebar-connection",
                                div { class: "sidebar-conn-status",
                                    div { class: "status-dot connected" }
                                    div { class: "sidebar-conn-host", "{host}" }
                                }
                                button {
                                    class: "sidebar-disconnect-btn",
                                    onclick: move |_| on_disconnect.call(()),
                                    "Disconnect"
                                }
                            }
                        } else {
                            div { class: "sidebar-connection",
                                div { class: "sidebar-conn-status",
                                    div { class: "status-dot disconnected" }
                                    span { class: "text-dim-sm", "Not connected" }
                                }
                            }
                        }
                    }
                }
            }

            // Downloads card
            div { class: "settings-card dashboard-card",
                div { class: "settings-card-header",
                    span { class: "settings-card-icon", Download { size: 16 } }
                    h2 { "Downloads" }
                }
                div { class: "settings-card-body",
                    if blackarch_downloaded {
                        div { class: "sidebar-download-status installed",
                            span { class: "text-success", "\u{2713}" }
                            span { "BlackArch" }
                            span { class: "text-dim-xs", "Ready" }
                        }
                        div { class: "i-use-arch-btw", "i use arch btw" }
                    } else if download_progress.is_some() {
                        div { class: "sidebar-download-status",
                            span { "Setting up BlackArch..." }
                            div { class: "download-progress",
                                div { class: "download-progress-fill indeterminate" }
                            }
                        }
                    } else if let Some(ref err) = setup_error {
                        div { class: "sidebar-download-error",
                            div { class: "setup-error-message", white_space: "pre-wrap",
                                {err.as_str()}
                            }
                            button {
                                class: "sidebar-download-btn",
                                onclick: move |_| on_start_download.call(()),
                                "Retry"
                            }
                        }
                    } else {
                        button {
                            class: "sidebar-download-btn",
                            onclick: move |_| on_start_download.call(()),
                            "Set up BlackArch"
                        }
                    }
                }
            }

            // Shell Mode card
            div { class: "settings-card dashboard-card",
                div { class: "settings-card-header",
                    span { class: "settings-card-icon", Settings { size: 16 } }
                    h2 { "Shell Mode" }
                }
                div { class: "settings-card-body",
                    div { class: "setting-row",
                        div { class: "setting-label",
                            div { class: "setting-name", "Shell Mode" }
                            div { class: "text-dim-xs",
                                if is_proot { "BlackArch proot" } else { "Native shell" }
                            }
                        }
                        div { class: "setting-controls",
                            div { class: "setting-toggle",
                                button {
                                    class: if !is_proot {
                                        if just_saved() == Some(ShellMode::Native) {
                                            "toggle-btn active saved"
                                        } else {
                                            "toggle-btn active"
                                        }
                                    } else {
                                        "toggle-btn"
                                    },
                                    onclick: move |_| on_toggle(ShellMode::Native),
                                    "Native"
                                }
                                button {
                                    class: if is_proot {
                                        if just_saved() == Some(ShellMode::Proot) {
                                            "toggle-btn active saved"
                                        } else {
                                            "toggle-btn active"
                                        }
                                    } else {
                                        "toggle-btn"
                                    },
                                    disabled: !blackarch_downloaded,
                                    onclick: move |_| {
                                        if blackarch_downloaded {
                                            on_toggle(ShellMode::Proot);
                                        }
                                    },
                                    title: if !blackarch_downloaded { "Set up BlackArch environment first" } else { "" },
                                    "Proot"
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
