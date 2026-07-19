//! Settings page — Connection, Downloads, Shell Mode, and Appearance controls
//! with form change tracking (original/discard pattern).

use dioxus::prelude::*;
use pentest_core::config::{BorderRadius, Density, ShellMode, Theme};
use pentest_platform::WifiConnectionStatus;
use std::collections::HashSet;

use super::icons::{ChevronDown, Download, Palette, Settings, Wifi};
use super::tool_category::{category_icon, humanize_category};
use crate::platform_helper;
use pentest_core::seed::{SeedManager, SeedProgress, SeedTier};

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
    // Appearance settings
    theme: Theme,
    on_theme_change: EventHandler<Theme>,
    border_radius: BorderRadius,
    on_border_radius_change: EventHandler<BorderRadius>,
    density: Density,
    on_density_change: EventHandler<Density>,
    #[props(default)] on_theme_imported: EventHandler<()>,
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

    // WiFi adapter state
    let original_wifi_adapter = use_hook(|| wifi_adapter.clone());
    let mut local_wifi_adapter = use_signal(|| wifi_adapter.clone());
    let mut wifi_status = use_signal(|| None::<WifiConnectionStatus>);
    let mut wifi_loading = use_signal(|| false);
    let mut wifi_test_result = use_signal(|| None::<Result<String, String>>);
    let mut wifi_testing = use_signal(|| false);

    // Resource seeding state
    let mut seed_status = use_signal(|| None::<Vec<(String, bool)>>);
    let mut seed_loading = use_signal(|| false);
    let mut seed_progress = use_signal(|| None::<SeedProgress>);
    let mut seed_result = use_signal(|| None::<Result<String, String>>);

    // Export session state
    let mut export_loading = use_signal(|| false);
    let mut export_result = use_signal(|| None::<Result<String, String>>);

    // Tools catalog state
    let mut catalog_items = use_signal(|| None::<Vec<pentest_tools::catalog::CatalogItem>>);
    let mut catalog_loading = use_signal(|| false);
    // Category keys the operator has expanded. Categories are collapsed by
    // default (empty set) so the panel stays compact even as the catalog grows;
    // a collapsed category renders only its header, not its cards.
    let mut expanded_categories = use_signal(HashSet::<String>::new);
    // binary_name currently installing, the "__all__" sentinel for the bulk
    // install, or a "cat:<key>" sentinel for a category "install all"; None when
    // idle. Any Some(..) value disables the other install buttons.
    let mut installing = use_signal(|| None::<String>);
    let mut install_message = use_signal(String::new);
    let mut install_error = use_signal(|| None::<String>);
    // A pending category "Install all", if any: (category_key, count,
    // total_estimated_secs). Some(..) shows the confirm dialog so a bulk install
    // is never kicked off without the operator seeing how many tools it fetches.
    let mut category_install_confirm = use_signal(|| None::<(String, usize, u32)>);
    // Seconds elapsed since the current install began, ticked once a second by a
    // background task while `installing` is Some. Drives the elapsed-vs-estimate
    // progress bar so the operator can see how long an install is taking.
    let mut install_elapsed = use_signal(|| 0u32);
    // Expected duration (seconds) for the current install; 0 hides the estimate.
    let mut install_estimate = use_signal(|| 0u32);
    // Monotonic id for the current install session, bumped each time an install
    // starts. A ticker captures the generation it was spawned for and stops as
    // soon as a newer session begins, so a stale ticker can't advance the clock
    // for a later install — even a restart of the same tool, where `installing`
    // would otherwise look unchanged.
    let mut install_generation = use_signal(|| 0u64);
    // The tool pending an uninstall confirmation, if any. Some(item) shows the
    // confirm dialog; cleared to None on cancel or after removal completes.
    let mut uninstall_confirm = use_signal(|| None::<pentest_tools::catalog::CatalogItem>);
    // binary_name currently being uninstalled, or None when idle. Disables the
    // trash-cans and shows a per-card "Removing..." state.
    let mut uninstalling = use_signal(|| None::<String>);

    // Load seed status on mount
    use_effect(move || {
        spawn(async move {
            let manager = SeedManager::new();
            let status = manager.check_status().await;
            seed_status.set(Some(status));
        });
    });

    // Load tool catalog on mount
    use_effect(move || {
        spawn(async move {
            catalog_loading.set(true);
            let items = pentest_tools::catalog::build_catalog_items().await;
            catalog_items.set(Some(items));
            catalog_loading.set(false);
        });
    });

    // Tick the install elapsed clock once a second while an install is running.
    // Reads `installing`/`install_generation` reactively, so the effect re-runs
    // whenever an install starts, stops, or is replaced. The spawned loop
    // captures the generation it was started for and exits as soon as a newer
    // session begins; because a fresh session always bumps the generation, a
    // stale ticker cannot advance the clock for a later install (including a
    // restart of the same tool). The clock is reset here so the reset is atomic
    // with the ticker spawn rather than racing the onclick handlers.
    use_effect(move || {
        if installing().is_none() {
            return;
        }
        let generation = install_generation();
        install_elapsed.set(0);
        spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                // Stop if this session was superseded or the install finished.
                if install_generation() != generation || installing().is_none() {
                    break;
                }
                install_elapsed.set(install_elapsed() + 1);
            }
        });
    });

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

    let wifi_adapter_changed = local_wifi_adapter() != original_wifi_adapter;

    // Theme import state
    let mut theme_import_path = use_signal(String::new);
    let mut theme_import_status = use_signal(|| None::<Result<String, String>>);
    let mut theme_importing = use_signal(|| false);
    let mut advanced_expanded = use_signal(|| false);

    // Check if save is safe (not selecting active connection)
    let save_wifi_disabled = if wifi_adapter_changed {
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

    // Handler: save WiFi adapter selection
    let on_save_wifi = {
        let on_wifi_adapter_change = on_wifi_adapter_change;
        move |_| {
            if let Some(status) = wifi_status.read().as_ref() {
                if let Some(ref selected) = local_wifi_adapter() {
                    if status.active_interface.as_ref() == Some(selected)
                        && status.connected_via_wifi
                    {
                        tracing::warn!("Prevented saving: user tried to select active connection");
                        return;
                    }
                }
            }
            on_wifi_adapter_change.call(local_wifi_adapter());
        }
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

            // Tools card
            div { class: "settings-card dashboard-card",
                div { class: "settings-card-header",
                    span { class: "settings-card-icon", Download { size: 16 } }
                    h2 { "Tools" }
                }
                div { class: "settings-card-body",
                    if let Some(ref err) = install_error() {
                        div { class: "sidebar-download-error",
                            div { class: "setup-error-message", white_space: "pre-wrap",
                                {err.as_str()}
                            }
                        }
                    }

                    // Install all recommended (bulk) action
                    if installing() == Some("__all__".to_string()) {
                        {
                            let (fraction, label) = install_progress(install_elapsed(), install_estimate());
                            rsx! {
                                div { class: "sidebar-download-status",
                                    span { "Installing recommended tools... {install_message}" }
                                    div { class: "download-progress",
                                        if install_estimate() > 0 {
                                            div {
                                                class: "download-progress-fill",
                                                style: "width: {fraction * 100.0}%",
                                            }
                                        } else {
                                            div { class: "download-progress-fill indeterminate" }
                                        }
                                    }
                                    div { class: "text-dim-xs", "{label}" }
                                }
                            }
                        }
                    } else {
                        button {
                            class: "sidebar-download-btn",
                            disabled: installing().is_some(),
                            onclick: move |_| {
                                // Estimate the bulk install as the sum of the
                                // pending recommended, auto-installable entries.
                                let estimate = catalog_items()
                                    .map(|items| {
                                        items
                                            .iter()
                                            .filter(|i| {
                                                i.recommended
                                                    && i.auto_installable
                                                    && i.state != "installed"
                                            })
                                            .map(|i| i.estimated_secs)
                                            .sum::<u32>()
                                    })
                                    .unwrap_or(0);
                                spawn(async move {
                                    use tokio::sync::mpsc;
                                    // Bump the session id so any stale ticker
                                    // stops; the ticker effect resets the clock.
                                    install_generation.set(install_generation() + 1);
                                    install_estimate.set(estimate);
                                    installing.set(Some("__all__".to_string()));
                                    install_error.set(None);
                                    install_message.set(String::new());
                                    let (tx, mut rx) = mpsc::unbounded_channel();
                                    spawn(async move {
                                        while let Some(msg) = rx.recv().await {
                                            install_message.set(msg);
                                        }
                                    });
                                    let progress = move |evt: pentest_tools::installers::InstallEvent| {
                                        let _ = tx.send(evt.message);
                                    };
                                    let failures =
                                        pentest_tools::catalog::install_all_recommended(&progress).await;
                                    if !failures.is_empty() {
                                        let detail = failures
                                            .iter()
                                            .map(|(bin, err)| format!("{bin}: {err}"))
                                            .collect::<Vec<_>>()
                                            .join("\n");
                                        install_error.set(Some(format!(
                                            "Some tools failed to install:\n{detail}"
                                        )));
                                    }
                                    let items = pentest_tools::catalog::build_catalog_items().await;
                                    catalog_items.set(Some(items));
                                    installing.set(None);
                                });
                            },
                            "Install all recommended"
                        }
                    }

                    if catalog_items().is_none() && catalog_loading() {
                        div { class: "text-dim-xs", style: "margin-top: 12px;", "Loading tools..." }
                    } else if let Some(items) = catalog_items() {
                        for category in tool_categories(&items) {
                            {
                                let count = items.iter().filter(|i| i.category == category).count();
                                let is_expanded = expanded_categories().contains(&category);
                                let toggle_category = category.clone();
                                // Tools in this category that an "Install all" would fetch:
                                // not yet installed and auto-installable in the current mode.
                                let pending: Vec<_> = items
                                    .iter()
                                    .filter(|i| {
                                        i.category == category
                                            && i.state != "installed"
                                            && i.auto_installable
                                    })
                                    .collect();
                                let pending_count = pending.len();
                                let pending_secs: u32 =
                                    pending.iter().map(|i| i.estimated_secs).sum();
                                rsx! {
                            div { class: "settings-tools-section",
                                div {
                                    class: "settings-tools-header",
                                    role: "button",
                                    tabindex: 0,
                                    "aria-expanded": "{is_expanded}",
                                    onclick: move |_| {
                                        let mut set = expanded_categories.write();
                                        if !set.remove(&toggle_category) {
                                            set.insert(toggle_category.clone());
                                        }
                                    },
                                    onkeydown: {
                                        let key_category = category.clone();
                                        move |evt: Event<KeyboardData>| {
                                            let key = evt.key();
                                            if key == Key::Enter
                                                || matches!(key, Key::Character(ref c) if c == " ")
                                            {
                                                evt.prevent_default();
                                                let mut set = expanded_categories.write();
                                                if !set.remove(&key_category) {
                                                    set.insert(key_category.clone());
                                                }
                                            }
                                        }
                                    },
                                    span {
                                        class: if is_expanded { "settings-tools-caret expanded" } else { "settings-tools-caret" },
                                        ChevronDown { size: 14 }
                                    }
                                    span { class: "settings-tools-icon", {category_icon(&category)} }
                                    h3 { class: "settings-tools-title", "{humanize_category(&category)}" }
                                    span { class: "settings-tools-count", "{count}" }
                                    // "Install all" for the category: shown only when
                                    // something is actually installable. Opens a confirm
                                    // dialog (count + estimate) rather than installing on
                                    // the first click. stop_propagation so it doesn't also
                                    // toggle the header's expand/collapse.
                                    if pending_count > 0 {
                                        button {
                                            class: "settings-tools-install-all",
                                            r#type: "button",
                                            disabled: installing().is_some(),
                                            title: "Install the {pending_count} not-installed tool(s) in this category",
                                            onclick: {
                                                let cat = category.clone();
                                                move |evt: Event<MouseData>| {
                                                    evt.stop_propagation();
                                                    category_install_confirm.set(Some((
                                                        cat.clone(),
                                                        pending_count,
                                                        pending_secs,
                                                    )));
                                                }
                                            },
                                            "\u{2193} Install all"
                                        }
                                    }
                                }
                                if is_expanded {
                                div { class: "tools-grid",
                                    for item in items.iter().filter(|i| i.category == category).cloned() {
                                        {
                                            let desc = item.description.clone();
                                            if item.state == "installed" {
                                                let removing = uninstalling() == Some(item.binary_name.clone());
                                                rsx! {
                                                    div { class: "tool-status-card installed",
                                                        // Trash-can (top-right) opens the confirm
                                                        // dialog. Only shown when the tool can
                                                        // actually be removed in this mode.
                                                        if item.uninstallable {
                                                            button {
                                                                class: "tool-uninstall-btn",
                                                                r#type: "button",
                                                                disabled: uninstalling().is_some(),
                                                                title: "Uninstall {item.display_name}",
                                                                "aria-label": "Uninstall {item.display_name}",
                                                                onclick: {
                                                                    let confirm_item = item.clone();
                                                                    move |evt: Event<MouseData>| {
                                                                        evt.stop_propagation();
                                                                        uninstall_confirm.set(Some(confirm_item.clone()));
                                                                    }
                                                                },
                                                                "\u{1F5D1}"
                                                            }
                                                        }
                                                        div { class: "tool-status-card-name", "{item.display_name}" }
                                                        if !desc.is_empty() {
                                                            div { class: "tool-status-card-desc", title: "{desc}", "{desc}" }
                                                        }
                                                        if removing {
                                                            div { class: "tool-status-card-status muted", "Removing..." }
                                                        } else {
                                                            div { class: "tool-status-card-status installed",
                                                                "\u{2713} Installed"
                                                            }
                                                        }
                                                    }
                                                }
                                            } else if item.auto_installable {
                                                // Missing but installable. The card is a
                                                // div[role=button] (not a <button>) because it
                                                // holds block-level children — a <button> may only
                                                // contain phrasing content. tabindex + onkeydown
                                                // restore the keyboard/AT affordances a native
                                                // button would provide.
                                                let installing_this =
                                                    installing() == Some(item.binary_name.clone());
                                                let disabled = installing().is_some();
                                                // Shared install action, invoked from both click
                                                // and Enter/Space. Guards on `installing` so only
                                                // one install runs at a time (mirrors the old
                                                // `disabled` on every button).
                                                let start_install = {
                                                    let bin = item.binary_name.clone();
                                                    let estimate = item.estimated_secs;
                                                    move || {
                                                        if installing().is_some() {
                                                            return;
                                                        }
                                                        let bin = bin.clone();
                                                        spawn(async move {
                                                            use tokio::sync::mpsc;
                                                            // Bump the session id so any stale
                                                            // ticker stops; the ticker effect
                                                            // resets the clock.
                                                            install_generation.set(install_generation() + 1);
                                                            install_estimate.set(estimate);
                                                            installing.set(Some(bin.clone()));
                                                            install_error.set(None);
                                                            install_message.set(String::new());
                                                            let (tx, mut rx) = mpsc::unbounded_channel();
                                                            spawn(async move {
                                                                while let Some(msg) = rx.recv().await {
                                                                    install_message.set(msg);
                                                                }
                                                            });
                                                            let progress = move |evt: pentest_tools::installers::InstallEvent| {
                                                                let _ = tx.send(evt.message);
                                                            };
                                                            match pentest_tools::catalog::install_by_binary(&bin, &progress).await {
                                                                Ok(()) => {
                                                                    let items = pentest_tools::catalog::build_catalog_items().await;
                                                                    catalog_items.set(Some(items));
                                                                }
                                                                Err(e) => install_error.set(Some(e.to_string())),
                                                            }
                                                            installing.set(None);
                                                        });
                                                    }
                                                };
                                                rsx! {
                                                    div {
                                                        class: "tool-status-card missing",
                                                        role: "button",
                                                        tabindex: if disabled { -1 } else { 0 },
                                                        "aria-disabled": "{disabled}",
                                                        onclick: {
                                                            let start = start_install.clone();
                                                            move |_| start()
                                                        },
                                                        onkeydown: {
                                                            let start = start_install.clone();
                                                            move |evt: Event<KeyboardData>| {
                                                                let key = evt.key();
                                                                if key == Key::Enter
                                                                    || matches!(key, Key::Character(ref c) if c == " ")
                                                                {
                                                                    evt.prevent_default();
                                                                    start();
                                                                }
                                                            }
                                                        },
                                                        div { class: "tool-status-card-name", "{item.display_name}" }
                                                        if !desc.is_empty() {
                                                            div { class: "tool-status-card-desc", title: "{desc}", "{desc}" }
                                                        }
                                                        if installing_this {
                                                            {
                                                                let (fraction, label) = install_progress(install_elapsed(), install_estimate());
                                                                rsx! {
                                                                    div { class: "tool-status-card-status action",
                                                                        "Installing... {install_message}"
                                                                    }
                                                                    div { class: "download-progress",
                                                                        if install_estimate() > 0 {
                                                                            div {
                                                                                class: "download-progress-fill",
                                                                                style: "width: {fraction * 100.0}%",
                                                                            }
                                                                        } else {
                                                                            div { class: "download-progress-fill indeterminate" }
                                                                        }
                                                                    }
                                                                    div { class: "tool-status-card-status muted", "{label}" }
                                                                }
                                                            }
                                                        } else {
                                                            div { class: "tool-status-card-status action",
                                                                "\u{2193} Install"
                                                            }
                                                        }
                                                    }
                                                }
                                            } else if let Some(instructions) = item.manual_instructions.clone() {
                                                rsx! {
                                                    div { class: "tool-status-card manual",
                                                        div { class: "tool-status-card-name", "{item.display_name}" }
                                                        div { class: "tool-status-card-status muted", "Manual install" }
                                                        div {
                                                            class: "tool-status-card-instructions",
                                                            title: "{instructions}",
                                                            "{instructions}"
                                                        }
                                                    }
                                                }
                                            } else {
                                                let status_text = if item.state == "manual" {
                                                    "Manual"
                                                } else if item.state == "missing" {
                                                    "Not installed"
                                                } else {
                                                    "Unknown"
                                                };
                                                rsx! {
                                                    div { class: "tool-status-card manual",
                                                        div { class: "tool-status-card-name", "{item.display_name}" }
                                                        if !desc.is_empty() {
                                                            div { class: "tool-status-card-desc", title: "{desc}", "{desc}" }
                                                        }
                                                        div { class: "tool-status-card-status muted", "{status_text}" }
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
                        }
                    } else {
                        div { class: "text-dim-xs", style: "margin-top: 12px;", "No tools available" }
                    }
                }
            }

            // Uninstall confirmation dialog. Destructive action, so it is always
            // gated behind an explicit confirm that names the package and warns
            // about other tools that share the dependency (blast radius).
            if let Some(target) = uninstall_confirm() {
                {
                    let bin = target.binary_name.clone();
                    // Other tools that declared this same binary dependency. pacman
                    // -Rns keeps deps still needed by another package, but removing a
                    // shared binary can still break sibling tools, so surface them.
                    let shared_with: Vec<String> = target
                        .used_by
                        .iter()
                        .filter(|t| **t != target.display_name && **t != target.binary_name)
                        .cloned()
                        .collect();
                    rsx! {
                        div { class: "uninstall-dialog-overlay",
                            onclick: move |_| uninstall_confirm.set(None),
                            div { class: "uninstall-dialog",
                                onclick: move |evt: Event<MouseData>| evt.stop_propagation(),
                                h3 { class: "uninstall-dialog-title", "Uninstall {target.display_name}?" }
                                div { class: "uninstall-dialog-body",
                                    "This removes the "
                                    span { class: "uninstall-dialog-pkg", "{target.binary_name}" }
                                    " package and its unneeded dependencies."
                                }
                                if !shared_with.is_empty() {
                                    div { class: "uninstall-dialog-warning",
                                        "Heads up: this dependency is also used by "
                                        strong { "{shared_with.join(\", \")}" }
                                        ". Removing it may affect those tools."
                                    }
                                }
                                div { class: "uninstall-dialog-actions",
                                    button {
                                        class: "settings-discard-btn",
                                        r#type: "button",
                                        onclick: move |_| uninstall_confirm.set(None),
                                        "Cancel"
                                    }
                                    button {
                                        class: "uninstall-dialog-confirm-btn",
                                        r#type: "button",
                                        disabled: uninstalling().is_some(),
                                        onclick: move |_| {
                                            let bin = bin.clone();
                                            uninstall_confirm.set(None);
                                            spawn(async move {
                                                use tokio::sync::mpsc;
                                                uninstalling.set(Some(bin.clone()));
                                                install_error.set(None);
                                                let (tx, mut rx) = mpsc::unbounded_channel();
                                                spawn(async move {
                                                    while let Some(msg) = rx.recv().await {
                                                        install_message.set(msg);
                                                    }
                                                });
                                                let progress = move |evt: pentest_tools::installers::InstallEvent| {
                                                    let _ = tx.send(evt.message);
                                                };
                                                match pentest_tools::catalog::uninstall_by_binary(&bin, &progress).await {
                                                    Ok(()) => {
                                                        let items = pentest_tools::catalog::build_catalog_items().await;
                                                        catalog_items.set(Some(items));
                                                    }
                                                    Err(e) => install_error.set(Some(e.to_string())),
                                                }
                                                uninstalling.set(None);
                                            });
                                        },
                                        "Uninstall"
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Category "Install all" confirmation. A bulk install can fetch
            // several packages, so it is always gated behind a confirm that
            // states the count and an estimated time before anything downloads.
            if let Some((cat, n, secs)) = category_install_confirm() {
                {
                    let label = humanize_category(&cat);
                    rsx! {
                        div { class: "settings-dialog-overlay",
                            onclick: move |_| category_install_confirm.set(None),
                            div { class: "settings-dialog",
                                onclick: move |evt: Event<MouseData>| evt.stop_propagation(),
                                h3 { class: "settings-dialog-title", "Install all {label} tools?" }
                                div { class: "settings-dialog-body",
                                    "This will install "
                                    span { class: "settings-dialog-emph", "{n}" }
                                    if n == 1 { " tool" } else { " tools" }
                                    " in this category (est. ~{format_duration(secs)})."
                                }
                                div { class: "settings-dialog-actions",
                                    button {
                                        class: "settings-discard-btn",
                                        r#type: "button",
                                        onclick: move |_| category_install_confirm.set(None),
                                        "Cancel"
                                    }
                                    button {
                                        class: "sidebar-download-btn",
                                        r#type: "button",
                                        disabled: installing().is_some(),
                                        onclick: move |_| {
                                            let cat = cat.clone();
                                            category_install_confirm.set(None);
                                            spawn(async move {
                                                use tokio::sync::mpsc;
                                                install_generation.set(install_generation() + 1);
                                                install_estimate.set(secs);
                                                installing.set(Some(format!("cat:{cat}")));
                                                install_error.set(None);
                                                install_message.set(String::new());
                                                let (tx, mut rx) = mpsc::unbounded_channel();
                                                spawn(async move {
                                                    while let Some(msg) = rx.recv().await {
                                                        install_message.set(msg);
                                                    }
                                                });
                                                let progress = move |evt: pentest_tools::installers::InstallEvent| {
                                                    let _ = tx.send(evt.message);
                                                };
                                                let failures = pentest_tools::catalog::install_all_in_category(&cat, &progress).await;
                                                if !failures.is_empty() {
                                                    let detail = failures
                                                        .iter()
                                                        .map(|(bin, err)| format!("{bin}: {err}"))
                                                        .collect::<Vec<_>>()
                                                        .join("\n");
                                                    install_error.set(Some(format!(
                                                        "Some tools failed to install:\n{detail}"
                                                    )));
                                                }
                                                let items = pentest_tools::catalog::build_catalog_items().await;
                                                catalog_items.set(Some(items));
                                                installing.set(None);
                                            });
                                        },
                                        "Install {n}"
                                    }
                                }
                            }
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
                                            wifi_test_result.set(None);
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
                                        if wifi_testing() { "Testing..." } else { "Test" }
                                    }
                                }
                            }

                            if let Some(Ok(ref msg)) = wifi_test_result.read().as_ref() {
                                div { class: "wifi-test-success", "✓ {msg}" }
                            }
                            if let Some(Err(ref err_msg)) = wifi_test_result.read().as_ref() {
                                div { class: "wifi-test-error", "✗ Test failed: {err_msg}" }
                            }

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

            // Appearance card
            div { class: "settings-card dashboard-card",
                div { class: "settings-card-header",
                    span { class: "settings-card-icon", Palette { size: 16 } }
                    h2 { "Appearance" }
                }
                div { class: "settings-card-body",
                    // Keyboard shortcuts hint
                    div {
                        style: "padding: 8px 12px; background: var(--accent); border-radius: var(--radius-md); margin-bottom: 16px; font-size: 12px; color: var(--accent-foreground);",
                        "💡 Tip: Press Ctrl+Shift+1-8 for quick theme switching"
                    }
                    // Theme selector with random button
                    div { class: "input-group",
                        label { "Theme" }
                        div { style: "display: flex; gap: 8px; align-items: center;",
                            select {
                                style: "flex: 1;",
                                value: "{theme:?}",
                                onchange: move |e| {
                                    let theme_str = e.value();
                                    let new_theme = match theme_str.as_str() {
                                        "Strike48" => Theme::Strike48,
                                        "Dark" => Theme::Dark,
                                        "Light" => Theme::Light,
                                        "Dracula" => Theme::Dracula,
                                        "Gruvbox" => Theme::Gruvbox,
                                        "TokyoNight" => Theme::TokyoNight,
                                        "Matrix" => Theme::Matrix,
                                        "Cyberpunk" => Theme::Cyberpunk,
                                        "Nord" => Theme::Nord,
                                        _ => Theme::Strike48,
                                    };
                                    on_theme_change.call(new_theme);
                                },
                                option { value: "Strike48", "Strike48" }
                                option { value: "Dark", "Dark" }
                                option { value: "Light", "Light" }
                                option { value: "Dracula", "Dracula" }
                                option { value: "Gruvbox", "Gruvbox" }
                                option { value: "TokyoNight", "Tokyo Night" }
                                option { value: "Matrix", "Matrix" }
                                option { value: "Cyberpunk", "Cyberpunk" }
                                option { value: "Nord", "Nord" }
                            }
                            button {
                                class: "button button-secondary",
                                style: "padding: 8px 12px; min-width: auto;",
                                title: "Random theme",
                                onclick: move |_| {
                                    let all_themes = [
                                        Theme::Strike48,
                                        Theme::Dark,
                                        Theme::Light,
                                        Theme::Dracula,
                                        Theme::Gruvbox,
                                        Theme::TokyoNight,
                                        Theme::Matrix,
                                        Theme::Cyberpunk,
                                        Theme::Nord,
                                    ];

                                    // Get random theme different from current
                                    let candidates: Vec<Theme> = all_themes
                                        .iter()
                                        .copied()
                                        .filter(|t| *t != theme)
                                        .collect();

                                    if !candidates.is_empty() {
                                        // Simple pseudo-random using timestamp
                                        let timestamp = std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .unwrap()
                                            .as_nanos();

                                        let idx = (timestamp % candidates.len() as u128) as usize;
                                        let new_theme = candidates[idx];
                                        on_theme_change.call(new_theme);
                                    }
                                },
                                "🎲"
                            }
                        }
                    }

                    // Border radius selector
                    div { class: "input-group",
                        label { "Border Radius" }
                        select {
                            value: "{border_radius:?}",
                            onchange: move |e| {
                                let radius_str = e.value();
                                let new_radius = match radius_str.as_str() {
                                    "Sharp" => BorderRadius::Sharp,
                                    "Minimal" => BorderRadius::Minimal,
                                    "Rounded" => BorderRadius::Rounded,
                                    "Soft" => BorderRadius::Soft,
                                    "Pill" => BorderRadius::Pill,
                                    _ => BorderRadius::Rounded,
                                };
                                on_border_radius_change.call(new_radius);
                            },
                            option { value: "Sharp", "Sharp (0px)" }
                            option { value: "Minimal", "Minimal (4px)" }
                            option { value: "Rounded", "Rounded (8px)" }
                            option { value: "Soft", "Soft (16px)" }
                            option { value: "Pill", "Pill (999px)" }
                        }
                    }

                    // Density selector
                    div { class: "input-group",
                        label { "Density" }
                        select {
                            value: "{density:?}",
                            onchange: move |e| {
                                let density_str = e.value();
                                let new_density = match density_str.as_str() {
                                    "Compact" => Density::Compact,
                                    "Normal" => Density::Normal,
                                    "Comfortable" => Density::Comfortable,
                                    _ => Density::Normal,
                                };
                                on_density_change.call(new_density);
                            },
                            option { value: "Compact", "Compact" }
                            option { value: "Normal", "Normal" }
                            option { value: "Comfortable", "Comfortable" }
                        }
                    }

                    // Advanced section (collapsible)
                    div { class: "input-group", style: "margin-top: 16px; border-top: 1px solid var(--border); padding-top: 16px;",
                        div {
                            style: "display: flex; align-items: center; gap: 8px; cursor: pointer;",
                            onclick: move |_| advanced_expanded.set(!advanced_expanded()),
                            span {
                                style: format!("transform: rotate({}deg); transition: transform 0.2s;", if advanced_expanded() { 90 } else { 0 }),
                                "▸"
                            }
                            label { style: "cursor: pointer; margin: 0;", "Advanced" }
                        }

                        if advanced_expanded() {
                            div { style: "margin-top: 12px;",
                                label { "Import Custom Theme" }
                                div { style: "display: flex; gap: 8px;",
                                    input {
                                        r#type: "text",
                                        placeholder: "/path/to/theme.css",
                                        value: "{theme_import_path}",
                                        disabled: theme_importing(),
                                        oninput: move |e| theme_import_path.set(e.value()),
                                    }
                                    button {
                                        disabled: theme_importing() || theme_import_path().is_empty(),
                                        onclick: move |_| {
                                            let path = theme_import_path();
                                            if path.is_empty() {
                                                return;
                                            }

                                            theme_importing.set(true);
                                            theme_import_status.set(None);

                                            spawn(async move {
                                                // Import and validate theme file (blocking I/O in spawn)
                                                let result = match pentest_core::theme_loader::import_theme_file(&path) {
                                                    Ok(dest_path) => {
                                                        // Validate the imported theme
                                                        match pentest_core::theme_loader::load_theme_file(&dest_path) {
                                                            Ok(content) => {
                                                                match crate::theme::parse_theme_file(&content) {
                                                                    Ok(theme) => {
                                                                        // Validate CSS security
                                                                        if let Some(custom_css) = &theme.custom_css {
                                                                            if let Err(errors) = crate::theme::validate_custom_css(custom_css) {
                                                                                let _ = std::fs::remove_file(&dest_path);
                                                                                Err(format!("Theme validation failed:\n{}", errors.join("\n")))
                                                                            } else {
                                                                                Ok(format!("Theme '{}' imported successfully!", theme.metadata.name))
                                                                            }
                                                                        } else {
                                                                            Ok(format!("Theme '{}' imported successfully!", theme.metadata.name))
                                                                        }
                                                                    }
                                                                    Err(e) => {
                                                                        let _ = std::fs::remove_file(&dest_path);
                                                                        Err(format!("Invalid theme format: {}", e))
                                                                    }
                                                                }
                                                            }
                                                            Err(e) => Err(format!("Failed to read theme: {}", e)),
                                                        }
                                                    }
                                                    Err(e) => Err(format!("Import failed: {}", e)),
                                                };

                                                theme_import_status.set(Some(result.clone()));
                                                theme_importing.set(false);
                                                theme_import_path.set(String::new());

                                                if result.is_ok() {
                                                    on_theme_imported.call(());
                                                }
                                            });
                                        },
                                        if theme_importing() {
                                            "Importing..."
                                        } else {
                                            "Import"
                                        }
                                    }
                                }

                                // Show import status
                                if let Some(status) = theme_import_status() {
                                    match status {
                                        Ok(ref msg) => rsx! { div { class: "text-success-xs", style: "margin-top: 4px;", "{msg}" } },
                                        Err(ref err) => rsx! { div { class: "text-error-xs", style: "margin-top: 4px; white-space: pre-wrap;", "{err}" } },
                                    }
                                }

                                div { class: "text-dim-xs", style: "margin-top: 4px;",
                                    "Import .css theme files from disk. See themes/README.md for format."
                                }
                            }
                        }
                    }

                    // Info text
                    div { class: "text-dim-xs", style: "margin-top: 12px;",
                        "Theme changes apply instantly"
                    }
                }
            }

            // Save WiFi adapter — only visible when adapter changed
            if wifi_adapter_changed {
                div { class: "settings-actions",
                    button {
                        class: "settings-discard-btn",
                        onclick: move |_| local_wifi_adapter.set(original_wifi_adapter.clone()),
                        "Discard Changes"
                    }
                    button {
                        class: "settings-save-btn",
                        disabled: save_wifi_disabled,
                        onclick: on_save_wifi,
                        title: if save_wifi_disabled { "Cannot save: selected adapter is your active connection" } else { "" },
                        "Save"
                    }
                }
            }

            // Seed Resources card
            div { class: "settings-card dashboard-card",
                div { class: "settings-card-header",
                    span { class: "settings-card-icon", Download { size: 16 } }
                    h2 { "Seed Resources" }
                }
                div { class: "settings-card-body",
                    div { class: "text-dim-xs resource-description",
                        "Download wordlists and pentesting resources for offline use"
                    }

                    if seed_loading() {
                        div { class: "seed-loading",
                            if let Some(progress) = seed_progress() {
                                div { class: "seed-progress-info",
                                    div { class: "seed-progress-name", "{progress.resource_name}" }
                                    div { class: "seed-progress-bar",
                                        div {
                                            class: "seed-progress-fill",
                                            style: "width: {progress.percent}%"
                                        }
                                    }
                                    div { class: "seed-progress-text",
                                        "{progress.downloaded_mb:.1} MB / {progress.total_mb:.1} MB ({progress.percent}%)"
                                    }
                                }
                            } else {
                                div { class: "text-dim-xs", "Preparing to download..." }
                            }
                        }
                    } else {
                        div { class: "seed-tiers",
                            // Basic tier
                            div { class: "seed-tier",
                                div { class: "seed-tier-info",
                                    div { class: "seed-tier-header",
                                        div { class: "seed-tier-name", "Basic" }
                                        div { class: "seed-tier-size", "~150MB" }
                                    }
                                    div { class: "seed-tier-description text-dim-xs",
                                        "Essential wordlists, payloads, and fuzzing data"
                                    }
                                    if let Some(ref status) = seed_status() {
                                        div { class: "seed-tier-status text-dim-xs",
                                            {count_seeded_in_tier(status, &[
                                                "RockYou Wordlist",
                                                "Common Passwords",
                                                "Usernames",
                                                "Web Directories",
                                                "Reverse Shells",
                                                "XSS Payloads",
                                                "SQL Injection Payloads",
                                                "MAC Vendor Lookup (OUI)"
                                            ])}
                                        }
                                    }
                                }
                                // Check if Basic tier is fully seeded
                                if seed_status().as_ref().map(|s| is_tier_fully_seeded(s, &["RockYou Wordlist", "Common Passwords", "Usernames", "Web Directories", "Reverse Shells", "XSS Payloads", "SQL Injection Payloads", "MAC Vendor Lookup (OUI)"])).unwrap_or(false) {
                                    // Show disabled button with "Seeded" and re-download icon
                                    div { class: "seed-tier-btn-group",
                                            button {
                                                class: "seed-tier-btn seed-tier-btn-seeded",
                                                disabled: true,
                                                "Seeded"
                                            }
                                            button {
                                                class: "seed-tier-reseed-icon",
                                                disabled: seed_loading(),
                                                onclick: move |_| {
                                                    seed_loading.set(true);
                                                    seed_result.set(None);

                                                    spawn(async move {
                                                        use tokio::sync::mpsc;
                                                        let (tx, mut rx) = mpsc::unbounded_channel();
                                                        spawn(async move {
                                                            while let Some(progress) = rx.recv().await {
                                                                seed_progress.set(Some(progress));
                                                            }
                                                        });

                                                        let manager = SeedManager::new();
                                                        let result = manager.seed_tier_with_options(SeedTier::Basic, true, move |progress| {
                                                            let _ = tx.send(progress);
                                                        }).await;

                                                        seed_loading.set(false);
                                                        seed_progress.set(None);

                                                        match result {
                                                            Ok(summary) => {
                                                                seed_result.set(Some(Ok(format!(
                                                                    "Re-seeded {} resources successfully",
                                                                    summary.succeeded.len()
                                                                ))));
                                                                let status = manager.check_status().await;
                                                                seed_status.set(Some(status));
                                                            }
                                                            Err(e) => {
                                                                seed_result.set(Some(Err(e.to_string())));
                                                            }
                                                        }
                                                    });
                                                },
                                                title: "Force re-download all Basic tier resources",
                                                "↻"
                                            }
                                        }
                                    } else {
                                        // Show normal seed button
                                        button {
                                            class: "seed-tier-btn",
                                            disabled: seed_loading(),
                                            onclick: move |_| {
                                                seed_loading.set(true);
                                                seed_result.set(None);

                                                spawn(async move {
                                                    use tokio::sync::mpsc;
                                                    let (tx, mut rx) = mpsc::unbounded_channel();
                                                    spawn(async move {
                                                        while let Some(progress) = rx.recv().await {
                                                            seed_progress.set(Some(progress));
                                                        }
                                                    });

                                                    let manager = SeedManager::new();
                                                    let result = manager.seed_tier(SeedTier::Basic, move |progress| {
                                                        let _ = tx.send(progress);
                                                    }).await;

                                                    seed_loading.set(false);
                                                    seed_progress.set(None);

                                                    match result {
                                                        Ok(summary) => {
                                                            let msg = if summary.failed.is_empty() {
                                                                format!("Seeded {} resources successfully", summary.succeeded.len())
                                                            } else {
                                                                format!("Seeded {}/{} resources ({} failed)",
                                                                    summary.succeeded.len(),
                                                                    summary.succeeded.len() + summary.failed.len(),
                                                                    summary.failed.len())
                                                            };
                                                            seed_result.set(Some(if summary.failed.is_empty() { Ok(msg) } else { Err(msg) }));
                                                            let status = manager.check_status().await;
                                                            seed_status.set(Some(status));
                                                        }
                                                        Err(e) => {
                                                            seed_result.set(Some(Err(e.to_string())));
                                                        }
                                                    }
                                                });
                                            },
                                            "Seed Basic"
                                        }
                                }
                            }

                            // Enhanced tier
                            div { class: "seed-tier",
                                div { class: "seed-tier-info",
                                    div { class: "seed-tier-header",
                                        div { class: "seed-tier-name", "Enhanced" }
                                        div { class: "seed-tier-size", "~500MB" }
                                    }
                                    div { class: "seed-tier-description text-dim-xs",
                                        "Nuclei templates, ExploitDB index, GeoIP database"
                                    }
                                    if let Some(ref status) = seed_status() {
                                        div { class: "seed-tier-status text-dim-xs",
                                            {count_seeded_in_tier(status, &[
                                                "Nuclei Templates",
                                                "ExploitDB Index",
                                                "GeoIP Database",
                                                "Subdomains Wordlist",
                                                "API Endpoints"
                                            ])}
                                        }
                                    }
                                }
                                // Check if Enhanced tier is fully seeded
                                if seed_status().as_ref().map(|s| is_tier_fully_seeded(s, &["Nuclei Templates", "ExploitDB Index", "GeoIP Database", "Subdomains Wordlist", "API Endpoints"])).unwrap_or(false) {
                                    div { class: "seed-tier-btn-group",
                                        button {
                                            class: "seed-tier-btn seed-tier-btn-seeded",
                                            disabled: true,
                                            "Seeded"
                                        }
                                        button {
                                            class: "seed-tier-reseed-icon",
                                            disabled: seed_loading(),
                                            onclick: move |_| {
                                                seed_loading.set(true);
                                                seed_result.set(None);
                                                spawn(async move {
                                                    use tokio::sync::mpsc;
                                                    let (tx, mut rx) = mpsc::unbounded_channel();
                                                    spawn(async move {
                                                        while let Some(progress) = rx.recv().await {
                                                            seed_progress.set(Some(progress));
                                                        }
                                                    });
                                                    let manager = SeedManager::new();
                                                    let result = manager.seed_tier_with_options(SeedTier::Enhanced, true, move |progress| {
                                                        let _ = tx.send(progress);
                                                    }).await;
                                                    seed_loading.set(false);
                                                    seed_progress.set(None);
                                                    match result {
                                                        Ok(summary) => {
                                                            seed_result.set(Some(Ok(format!(
                                                                "Re-seeded {} resources successfully",
                                                                summary.succeeded.len()
                                                            ))));
                                                            let status = manager.check_status().await;
                                                            seed_status.set(Some(status));
                                                        }
                                                        Err(e) => {
                                                            seed_result.set(Some(Err(e.to_string())));
                                                        }
                                                    }
                                                });
                                            },
                                            title: "Force re-download all Enhanced tier resources",
                                            "↻"
                                        }
                                    }
                                } else {
                                    button {
                                        class: "seed-tier-btn",
                                        disabled: seed_loading(),
                                        onclick: move |_| {
                                            seed_loading.set(true);
                                            seed_result.set(None);
                                            spawn(async move {
                                                use tokio::sync::mpsc;
                                                let (tx, mut rx) = mpsc::unbounded_channel();
                                                spawn(async move {
                                                    while let Some(progress) = rx.recv().await {
                                                        seed_progress.set(Some(progress));
                                                    }
                                                });
                                                let manager = SeedManager::new();
                                                let result = manager.seed_tier(SeedTier::Enhanced, move |progress| {
                                                    let _ = tx.send(progress);
                                                }).await;
                                                seed_loading.set(false);
                                                seed_progress.set(None);
                                                match result {
                                                    Ok(summary) => {
                                                        let msg = if summary.failed.is_empty() {
                                                            format!("Seeded {} resources successfully", summary.succeeded.len())
                                                        } else {
                                                            format!("Seeded {}/{} resources ({} failed)",
                                                                summary.succeeded.len(),
                                                                summary.succeeded.len() + summary.failed.len(),
                                                                summary.failed.len())
                                                        };
                                                        seed_result.set(Some(if summary.failed.is_empty() { Ok(msg) } else { Err(msg) }));
                                                        let status = manager.check_status().await;
                                                        seed_status.set(Some(status));
                                                    }
                                                    Err(e) => {
                                                        seed_result.set(Some(Err(e.to_string())));
                                                    }
                                                }
                                            });
                                        },
                                        "Seed Enhanced"
                                    }
                                }
                            }

                            // Advanced tier
                            div { class: "seed-tier",
                                div { class: "seed-tier-info",
                                    div { class: "seed-tier-header",
                                        div { class: "seed-tier-name", "Advanced" }
                                        div { class: "seed-tier-size", "~2GB+" }
                                    }
                                    div { class: "seed-tier-description text-dim-xs",
                                        "Precompiled binaries, privilege escalation tools"
                                    }
                                    if let Some(ref status) = seed_status() {
                                        div { class: "seed-tier-status text-dim-xs",
                                            {count_seeded_in_tier(status, &[
                                                "LinPEAS Binary",
                                                "WinPEAS Binary",
                                                "Nmap Service Probes"
                                            ])}
                                        }
                                    }
                                }
                                // Check if Advanced tier is fully seeded
                                if seed_status().as_ref().map(|s| is_tier_fully_seeded(s, &["LinPEAS Binary", "WinPEAS Binary", "Nmap Service Probes"])).unwrap_or(false) {
                                    div { class: "seed-tier-btn-group",
                                        button {
                                            class: "seed-tier-btn seed-tier-btn-seeded",
                                            disabled: true,
                                            "Seeded"
                                        }
                                        button {
                                            class: "seed-tier-reseed-icon",
                                            disabled: seed_loading(),
                                            onclick: move |_| {
                                                seed_loading.set(true);
                                                seed_result.set(None);
                                                spawn(async move {
                                                    use tokio::sync::mpsc;
                                                    let (tx, mut rx) = mpsc::unbounded_channel();
                                                    let mut seed_progress = seed_progress;
                                                    spawn(async move {
                                                        while let Some(progress) = rx.recv().await {
                                                            seed_progress.set(Some(progress));
                                                        }
                                                    });
                                                    let manager = SeedManager::new();
                                                    let result = manager.seed_tier_with_options(SeedTier::Advanced, true, move |progress| {
                                                        let _ = tx.send(progress);
                                                    }).await;
                                                    seed_loading.set(false);
                                                    match result {
                                                        Ok(summary) => {
                                                            seed_result.set(Some(Ok(format!(
                                                                "Re-seeded {} resources successfully",
                                                                summary.succeeded.len()
                                                            ))));
                                                            let status = manager.check_status().await;
                                                            seed_status.set(Some(status));
                                                        }
                                                        Err(e) => {
                                                            seed_result.set(Some(Err(e.to_string())));
                                                        }
                                                    }
                                                });
                                            },
                                            title: "Force re-download all Advanced tier resources",
                                            "↻"
                                        }
                                    }
                                } else {
                                    button {
                                        class: "seed-tier-btn",
                                        disabled: seed_loading(),
                                        onclick: move |_| {
                                            seed_loading.set(true);
                                            seed_result.set(None);
                                            spawn(async move {
                                                use tokio::sync::mpsc;
                                                let (tx, mut rx) = mpsc::unbounded_channel();
                                                let mut seed_progress = seed_progress;
                                                spawn(async move {
                                                    while let Some(progress) = rx.recv().await {
                                                        seed_progress.set(Some(progress));
                                                    }
                                                });
                                                let manager = SeedManager::new();
                                                let result = manager.seed_tier(SeedTier::Advanced, move |progress| {
                                                    let _ = tx.send(progress);
                                                }).await;
                                                seed_loading.set(false);
                                                match result {
                                                    Ok(summary) => {
                                                        let msg = if summary.failed.is_empty() {
                                                            format!("Seeded {} resources successfully", summary.succeeded.len())
                                                        } else {
                                                            format!("Seeded {}/{} resources ({} failed)",
                                                                summary.succeeded.len(),
                                                                summary.succeeded.len() + summary.failed.len(),
                                                                summary.failed.len())
                                                        };
                                                        seed_result.set(Some(if summary.failed.is_empty() { Ok(msg) } else { Err(msg) }));
                                                        let status = manager.check_status().await;
                                                        seed_status.set(Some(status));
                                                    }
                                                    Err(e) => {
                                                        seed_result.set(Some(Err(e.to_string())));
                                                    }
                                                }
                                            });
                                        },
                                        "Seed Advanced"
                                    }
                                }
                            }
                        }

                        if let Some(Ok(ref msg)) = seed_result() {
                            div { class: "seed-result-success", "✓ {msg}" }
                        }
                        if let Some(Err(ref err)) = seed_result() {
                            div { class: "seed-result-error", "✗ Error: {err}" }
                        }

                        div { class: "seed-info text-dim-xs",
                            "Resources will be downloaded to ~/.pick/resources/"
                        }
                    }
                }

                // Export Session section
                div { class: "settings-card",
                    div { class: "settings-card-header",
                        h2 { "Export Session" }
                    }
                    div { class: "settings-card-body",
                        p { class: "text-dim-s",
                            "Export current session data to JSON or Markdown report for documentation, compliance, and evidence preservation."
                        }

                        div { class: "export-format-group",
                            button {
                                class: "export-btn",
                                disabled: export_loading(),
                                onclick: move |_| {
                                    export_loading.set(true);
                                    export_result.set(None);
                                    spawn(async move {
                                        use pentest_core::tools::ToolContext;

                                        let registry_arc = match crate::session::get_tool_registry() {
                                            Some(r) => r,
                                            None => {
                                                export_result.set(Some(Err("Tool registry not available".to_string())));
                                                export_loading.set(false);
                                                return;
                                            }
                                        };

                                        let ctx = ToolContext::default();
                                        let registry_guard = registry_arc.read().await;

                                        let params = serde_json::json!({
                                            "format": "json",
                                        });

                                        match registry_guard.execute("export_session", params, &ctx).await {
                                            Ok(result) => {
                                                if result.success {
                                                    if let Some(file_path) = result.data.get("file_path").and_then(|v| v.as_str()) {
                                                        export_result.set(Some(Ok(format!("Exported to {}", file_path))));
                                                    } else {
                                                        export_result.set(Some(Ok("Export successful".to_string())));
                                                    }
                                                } else {
                                                    let err = result.error.unwrap_or_else(|| "Export failed".to_string());
                                                    export_result.set(Some(Err(err)));
                                                }
                                            }
                                            Err(e) => {
                                                export_result.set(Some(Err(format!("Export error: {}", e))));
                                            }
                                        }
                                        export_loading.set(false);
                                    });
                                },
                                if export_loading() { "Exporting..." } else { "Export as JSON" }
                            }
                            button {
                                class: "export-btn",
                                disabled: export_loading(),
                                onclick: move |_| {
                                    export_loading.set(true);
                                    export_result.set(None);
                                    spawn(async move {
                                        use pentest_core::tools::ToolContext;

                                        let registry_arc = match crate::session::get_tool_registry() {
                                            Some(r) => r,
                                            None => {
                                                export_result.set(Some(Err("Tool registry not available".to_string())));
                                                export_loading.set(false);
                                                return;
                                            }
                                        };

                                        let ctx = ToolContext::default();
                                        let registry_guard = registry_arc.read().await;

                                        let params = serde_json::json!({
                                            "format": "markdown",
                                        });

                                        match registry_guard.execute("export_session", params, &ctx).await {
                                            Ok(result) => {
                                                if result.success {
                                                    if let Some(file_path) = result.data.get("file_path").and_then(|v| v.as_str()) {
                                                        export_result.set(Some(Ok(format!("Exported to {}", file_path))));
                                                    } else {
                                                        export_result.set(Some(Ok("Export successful".to_string())));
                                                    }
                                                } else {
                                                    let err = result.error.unwrap_or_else(|| "Export failed".to_string());
                                                    export_result.set(Some(Err(err)));
                                                }
                                            }
                                            Err(e) => {
                                                export_result.set(Some(Err(format!("Export error: {}", e))));
                                            }
                                        }
                                        export_loading.set(false);
                                    });
                                },
                                if export_loading() { "Exporting..." } else { "Export as Markdown" }
                            }
                        }

                        if let Some(Ok(ref msg)) = export_result() {
                            div { class: "seed-result-success", "✓ {msg}" }
                        }
                        if let Some(Err(ref err)) = export_result() {
                            div { class: "seed-result-error", "✗ Error: {err}" }
                        }

                        div { class: "export-info text-dim-xs",
                            "Exports will be saved to your workspace directory"
                        }
                    }
                }
            }

            }
        }
    }
}

/// Turn elapsed and estimated install seconds into a progress fraction
/// (`0.0..=0.95`) and a human label like `"0:42 elapsed · ~2:00 expected"`.
///
/// The fraction is capped below `1.0` while an install is running so the bar
/// never claims completion before the install actually finishes; if the install
/// overruns its estimate the bar holds near-full rather than resetting or
/// looking stuck. When no estimate is available the fraction is `0.0` (callers
/// render an indeterminate bar) and the label shows elapsed time only.
fn install_progress(elapsed_secs: u32, estimate_secs: u32) -> (f64, String) {
    let elapsed_label = format_duration(elapsed_secs);
    if estimate_secs == 0 {
        return (0.0, format!("{elapsed_label} elapsed"));
    }
    let fraction = (elapsed_secs as f64 / estimate_secs as f64).min(0.95);
    let label = format!(
        "{elapsed_label} elapsed \u{00b7} ~{} expected",
        format_duration(estimate_secs)
    );
    (fraction, label)
}

/// Format a whole-second duration as `M:SS` (or `H:MM:SS` once past an hour).
fn format_duration(secs: u32) -> String {
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if h > 0 {
        format!("{h}:{m:02}:{s:02}")
    } else {
        format!("{m}:{s:02}")
    }
}

/// Helper function to count how many resources in a tier are already seeded
fn count_seeded_in_tier(status: &[(String, bool)], tier_resources: &[&str]) -> String {
    let seeded = tier_resources
        .iter()
        .filter(|&&name| status.iter().any(|(s, exists)| s == name && *exists))
        .count();
    let total = tier_resources.len();

    if seeded == 0 {
        format!("Not seeded ({} resources)", total)
    } else if seeded == total {
        format!("✓ Complete ({}/{} seeded)", seeded, total)
    } else {
        format!("Partial ({}/{} seeded)", seeded, total)
    }
}

fn is_tier_fully_seeded(status: &[(String, bool)], tier_resources: &[&str]) -> bool {
    tier_resources
        .iter()
        .all(|&name| status.iter().any(|(s, exists)| s == name && *exists))
}

/// Distinct tool categories in catalog order (items arrive sorted by category).
fn tool_categories(items: &[pentest_tools::catalog::CatalogItem]) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    for item in items {
        if !seen.iter().any(|c| c == &item.category) {
            seen.push(item.category.clone());
        }
    }
    seen
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_duration_renders_minutes_and_hours() {
        assert_eq!(format_duration(0), "0:00");
        assert_eq!(format_duration(9), "0:09");
        assert_eq!(format_duration(75), "1:15");
        assert_eq!(format_duration(600), "10:00");
        assert_eq!(format_duration(3661), "1:01:01");
    }

    #[test]
    fn install_progress_with_no_estimate_is_indeterminate() {
        let (fraction, label) = install_progress(42, 0);
        assert_eq!(fraction, 0.0, "no estimate => indeterminate (0.0)");
        assert_eq!(label, "0:42 elapsed");
    }

    #[test]
    fn install_progress_fills_toward_estimate() {
        let (fraction, label) = install_progress(30, 120);
        assert!((fraction - 0.25).abs() < 1e-9, "30/120 = 0.25");
        assert_eq!(label, "0:30 elapsed \u{00b7} ~2:00 expected");
    }

    #[test]
    fn install_progress_caps_below_full_when_overrunning() {
        // Elapsed past the estimate must not claim 100% (or overflow past it).
        let (fraction, _) = install_progress(600, 120);
        assert!(
            (fraction - 0.95).abs() < 1e-9,
            "overrun must cap at 0.95, got {fraction}"
        );
    }
}
