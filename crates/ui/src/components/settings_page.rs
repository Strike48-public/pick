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
    let mut wifi_test_result = use_signal(|| None::<Result<String, String>>);
    let mut wifi_testing = use_signal(|| false);

    // Load WiFi adapters on mount
    use_effect(move || {
        let adapter = local_wifi_adapter();
        spawn(async move {
            wifi_loading.set(true);
            match platform_helper::check_wifi_status(adapter).await {
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

    // Check if save is safe (not selecting active connection)
    let save_disabled = if wifi_adapter_changed {
        if let Some(status) = wifi_status.read().as_ref() {
            if let Some(ref selected) = local_wifi_adapter() {
                status.active_interface.as_ref() == Some(selected) && status.connected_via_wifi
            } else {
                false
            }
        } else {
            false
        }
    } else {
        false
    };

    // Handler: save — propagate to parent and update baseline
    let on_save = {
        let on_shell_mode_change = on_shell_mode_change;
        let on_wifi_adapter_change = on_wifi_adapter_change;
        move |_| {
            if shell_mode_changed {
                on_shell_mode_change.call(local_shell_mode());
            }
            if wifi_adapter_changed {
                // Validation: prevent saving if selecting active connection
                if let Some(status) = wifi_status.read().as_ref() {
                    if let Some(ref selected) = local_wifi_adapter() {
                        if status.active_interface.as_ref() == Some(selected)
                            && status.connected_via_wifi
                        {
                            tracing::warn!(
                                "Prevented saving: user tried to select active connection"
                            );
                            return;
                        }
                    }
                }
                on_wifi_adapter_change.call(local_wifi_adapter());
            }
        }
    };

    // Handler: discard — revert to original
    let on_discard = move |_| {
        local_shell_mode.set(original_shell_mode);
        local_wifi_adapter.set(original_wifi_adapter.clone());
    };

    // Handler: test WiFi adapter
    let on_test_adapter = move |_| {
        let adapter_to_test = local_wifi_adapter();
        spawn(async move {
            wifi_testing.set(true);
            wifi_test_result.set(None);

            match platform_helper::test_wifi_adapter(adapter_to_test.clone()).await {
                Ok(msg) => {
                    wifi_test_result.set(Some(Ok(msg)));
                }
                Err(e) => {
                    wifi_test_result.set(Some(Err(e)));
                }
            }

            wifi_testing.set(false);
        });
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
                                    // Show active connection info prominently
                                    if let Some(ref active) = status.active_interface {
                                        if status.connected_via_wifi {
                                            div { class: "text-dim-xs wifi-active-connection",
                                                "🌐 Active Connection: "
                                                span { class: "active-adapter-name", "{active}" }
                                            }
                                        }
                                    }
                                    div { class: "text-dim-xs",
                                        {
                                            if let Some(ref selected) = local_wifi_adapter() {
                                                format!("Using {} for scanning", selected)
                                            } else {
                                                "Auto-detect first available".to_string()
                                            }
                                        }
                                    }
                                }
                                div { class: "setting-select-with-test",
                                    select {
                                        class: "setting-select",
                                        value: local_wifi_adapter().unwrap_or_default(),
                                        onchange: move |evt| {
                                            let value = evt.value();
                                            wifi_test_result.set(None); // Clear test result on change
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
                                                    " ⚠️ (YOUR INTERNET CONNECTION)"
                                                }
                                            }
                                        }
                                    }
                                    button {
                                        class: "test-adapter-btn",
                                        disabled: wifi_testing() || local_wifi_adapter().is_none(),
                                        onclick: on_test_adapter,
                                        title: if local_wifi_adapter().is_none() { "Select an adapter to test" } else { "Test this adapter" },
                                        if wifi_testing() {
                                            "Testing..."
                                        } else {
                                            "Test"
                                        }
                                    }
                                }
                            }

                            // Test result display - success
                            if let Some(Ok(ref msg)) = wifi_test_result.read().as_ref() {
                                div { class: "wifi-test-success",
                                    "✓ {msg}"
                                }
                            }

                            // Test result display - error
                            if let Some(Err(ref err_msg)) = wifi_test_result.read().as_ref() {
                                div { class: "wifi-test-error",
                                    "✗ Test failed: {err_msg}"
                                }
                            }

                            // Warning if selected adapter matches active connection
                            if let Some(ref selected) = local_wifi_adapter() {
                                if status.active_interface.as_ref() == Some(selected) {
                                    div { class: "wifi-adapter-danger",
                                        "⚠️ WARNING: You selected your active internet connection!"
                                        br {}
                                        "Scanning this adapter will disconnect you from the internet and disconnect Pick from Strike48."
                                        br {}
                                        "Please select a different adapter or connect an external WiFi adapter."
                                    }
                                }
                            }

                            // General warning if connected via WiFi and no safe adapter selected
                            if status.connected_via_wifi {
                                if local_wifi_adapter().is_none() {
                                    div { class: "wifi-adapter-warning",
                                        "⚠️ Connected via WiFi - Auto-detect mode"
                                        br {}
                                        if status.total_adapters == 1 {
                                            "You only have one WiFi adapter. Scanning will disconnect your connection."
                                        } else {
                                            "Auto-detect may pick your internet connection. Select a specific external adapter below."
                                        }
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
                        disabled: save_disabled,
                        onclick: on_save,
                        title: if save_disabled { "Cannot save: selected adapter is your active connection" } else { "" },
                        "Save"
                    }
                }
            }

            }
        }
    }
}
