//! Settings page — Connection, Downloads, and Shell Mode controls
//! with form change tracking (original/discard pattern).

use dioxus::prelude::*;
use pentest_core::config::ShellMode;
use pentest_platform::WifiConnectionStatus;

use super::icons::{Download, Settings, Wifi};
use crate::platform_helper;

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
    #[props(default)] wifi_adapter: Option<String>,
    #[props(default)] on_wifi_adapter_change: EventHandler<Option<String>>,
) -> Element {
    // -----------------------------------------------------------------------
    // Form change tracking
    // -----------------------------------------------------------------------

    // Capture the original shell mode when the component first mounts.
    let original_shell_mode = use_hook(|| shell_mode);

    // Local signal tracks what the user has selected (may differ from the
    // committed prop value while the user is toggling).
    let mut local_shell_mode = use_signal(|| shell_mode);

    // WiFi adapter state
    let original_wifi_adapter = use_hook(|| wifi_adapter.clone());
    let mut local_wifi_adapter = use_signal(|| wifi_adapter.clone());
    let mut wifi_status = use_signal(|| None::<WifiConnectionStatus>);
    let mut wifi_loading = use_signal(|| false);

    // Load WiFi adapters on mount
    use_effect(move || {
        spawn(async move {
            wifi_loading.set(true);
            match platform_helper::check_wifi_status().await {
                Ok(status) => wifi_status.set(Some(status)),
                Err(e) => tracing::warn!("Failed to load WiFi adapters: {}", e),
            }
            wifi_loading.set(false);
        });
    });

    // Keep local_shell_mode in sync when the parent prop changes (e.g. after
    // a save round-trips through the parent and comes back as a new prop).
    use_effect({
        let shell_mode = shell_mode;
        move || {
            local_shell_mode.set(shell_mode);
        }
    });

    let is_proot = local_shell_mode() == ShellMode::Proot;
    let shell_mode_changed = local_shell_mode() != original_shell_mode;
    let wifi_adapter_changed = local_wifi_adapter() != original_wifi_adapter;
    let has_changes = shell_mode_changed || wifi_adapter_changed;

    // Handler: save — propagate to parent and update baseline
    let on_save = {
        let on_shell_mode_change = on_shell_mode_change;
        let on_wifi_adapter_change = on_wifi_adapter_change;
        move |_| {
            if shell_mode_changed {
                on_shell_mode_change.call(local_shell_mode());
            }
            if wifi_adapter_changed {
                on_wifi_adapter_change.call(local_wifi_adapter());
            }
        }
    };

    // Handler: discard — revert to original
    let on_discard = move |_| {
        local_shell_mode.set(original_shell_mode);
        local_wifi_adapter.set(original_wifi_adapter.clone());
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
                            if err.contains("Docker") || err.contains("sandbox backend") {
                                div { class: "setup-help-text",
                                    p { "Docker is required to run the BlackArch sandbox on macOS." }
                                    p { "Install one of the following:" }
                                    ul {
                                        li {
                                            strong { "Colima" }
                                            " (lightweight, recommended): "
                                            code { "brew install colima docker && colima start" }
                                        }
                                        li {
                                            strong { "Docker Desktop" }
                                            ": "
                                            a {
                                                href: "https://docs.docker.com/desktop/install/mac-install/",
                                                target: "_blank",
                                                "docs.docker.com/desktop/install/mac-install"
                                            }
                                        }
                                        li {
                                            strong { "OrbStack" }
                                            ": "
                                            a {
                                                href: "https://orbstack.dev",
                                                target: "_blank",
                                                "orbstack.dev"
                                            }
                                        }
                                    }
                                    p { class: "text-dim-xs", "After installing, make sure the Docker daemon is running, then retry." }
                                }
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
                        div { class: "setting-toggle",
                            button {
                                class: if !is_proot { "toggle-btn active" } else { "toggle-btn" },
                                onclick: move |_| local_shell_mode.set(ShellMode::Native),
                                "Native"
                            }
                            button {
                                class: if is_proot { "toggle-btn active" } else { "toggle-btn" },
                                disabled: !blackarch_downloaded,
                                onclick: move |_| {
                                    if blackarch_downloaded {
                                        local_shell_mode.set(ShellMode::Proot);
                                    }
                                },
                                title: if !blackarch_downloaded { "Set up BlackArch environment first" } else { "" },
                                "Proot"
                            }
                        }
                    }
                }
            }

            // WiFi Adapter card
            div { class: "settings-card dashboard-card",
                div { class: "settings-card-header",
                    span { class: "settings-card-icon", Wifi { size: 16 } }
                    h2 { "WiFi Adapter" }
                }
                div { class: "settings-card-body",
                    if wifi_loading() {
                        div { class: "text-dim-xs", "Loading adapters..." }
                    } else if let Some(status) = wifi_status.read().as_ref() {
                        if status.all_wifi_interfaces.is_empty() {
                            div { class: "text-dim-xs",
                                "No WiFi adapters detected. Connect an external adapter for WiFi scanning."
                            }
                        } else {
                            div { class: "setting-row",
                                div { class: "setting-label",
                                    div { class: "setting-name", "Scanning Adapter" }
                                    div { class: "text-dim-xs",
                                        {
                                            if let Some(ref selected) = local_wifi_adapter() {
                                                format!("Using {}", selected)
                                            } else {
                                                "Auto-detect".to_string()
                                            }
                                        }
                                    }
                                }
                                div { class: "setting-select",
                                    select {
                                        value: local_wifi_adapter().unwrap_or_default(),
                                        onchange: move |evt| {
                                            let value = evt.value();
                                            if value.is_empty() {
                                                local_wifi_adapter.set(None);
                                            } else {
                                                local_wifi_adapter.set(Some(value));
                                            }
                                        },
                                        option { value: "", "Auto-detect (first available)" }
                                        for interface in &status.all_wifi_interfaces {
                                            option {
                                                value: "{interface}",
                                                selected: local_wifi_adapter().as_ref() == Some(interface),
                                                "{interface}"
                                                // Show if it's the active connection
                                                if status.active_interface.as_ref() == Some(interface) {
                                                    " (currently connected)"
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            // Warning if connected via WiFi
                            if status.connected_via_wifi {
                                div { class: "wifi-adapter-warning",
                                    "⚠️ Connected via WiFi"
                                    if status.total_adapters == 1 {
                                        " - Scanning will disconnect your connection"
                                    } else {
                                        " - Use external adapter to avoid disconnection"
                                    }
                                }
                            }

                            // Info about external adapters
                            div { class: "wifi-adapter-info",
                                "💡 For best results, use a dedicated external WiFi adapter. "
                                a {
                                    href: "https://github.com/Strike48-public/pick#recommended-wifi-adapters",
                                    target: "_blank",
                                    rel: "noopener noreferrer",
                                    "View recommended adapters →"
                                }
                            }
                        }
                    } else {
                        div { class: "text-dim-xs", "Failed to load WiFi adapters" }
                    }
                }
            }

            // Save / Discard actions — only visible when something changed
            if has_changes {
                div { class: "settings-actions",
                    button {
                        class: "settings-discard-btn",
                        onclick: on_discard,
                        "Discard Changes"
                    }
                    button {
                        class: "settings-save-btn",
                        onclick: on_save,
                        "Save"
                    }
                }
            }

            }
        }
    }
}
