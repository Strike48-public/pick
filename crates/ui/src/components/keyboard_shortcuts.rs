//! Global keyboard shortcuts wrapper component
//!
//! Wraps the application content and intercepts keydown events to provide
//! navigation shortcuts, chat panel toggle, and help modal toggle.
//! Keys are ignored when focus is inside an `<input>`, `<textarea>`, or
//! `<select>` element (checked via JS `document.activeElement`).

use super::sidebar::NavPage;
use dioxus::prelude::*;
use pentest_core::config::Theme;

/// Props for [`KeyboardShortcuts`].
#[derive(Props, Clone, PartialEq)]
pub struct KeyboardShortcutsProps {
    /// Navigate to a page.
    on_navigate: EventHandler<NavPage>,
    /// Toggle the help modal.
    on_toggle_help: EventHandler<()>,
    /// Signal controlling help-modal visibility (so Escape can close it).
    help_visible: bool,
    /// Signal controlling chat-panel visibility (so Escape can close it).
    chat_visible: bool,
    /// Close the help modal explicitly.
    on_close_help: EventHandler<()>,
    /// Close the chat panel explicitly.
    on_close_chat: EventHandler<()>,
    /// Change theme (optional, for Ctrl+Shift+1-8 shortcuts).
    #[props(default)]
    on_theme_change: Option<EventHandler<Theme>>,
    /// Konami code callback (optional).
    #[props(default)]
    on_konami: Option<EventHandler<()>>,
    /// The wrapped application content.
    children: Element,
}

/// Global keyboard shortcut listener.
///
/// Renders a wrapper `<div>` with `tabindex="0"` and an `onkeydown` handler.
/// A `use_effect` auto-focuses the wrapper on mount so shortcuts work
/// immediately without the user having to click first.
///
/// # Key bindings
///
/// | Key              | Action                    |
/// |------------------|---------------------------|
/// | `?`              | Toggle help modal         |
/// | `1`-`6`          | Navigate to page          |
/// | `c`              | Toggle chat panel         |
/// | `Esc`            | Close modal / panel       |
/// | `Ctrl+Shift+1-8` | Switch theme directly     |
/// | Konami code      | Activate easter egg       |
/// Konami code sequence: ↑ ↑ ↓ ↓ ← → ← → B A
const KONAMI_SEQUENCE: &[&str] = &[
    "ArrowUp",
    "ArrowUp",
    "ArrowDown",
    "ArrowDown",
    "ArrowLeft",
    "ArrowRight",
    "ArrowLeft",
    "ArrowRight",
    "b",
    "a",
];

#[component]
pub fn KeyboardShortcuts(props: KeyboardShortcutsProps) -> Element {
    // Konami code tracking
    let mut konami_sequence = use_signal(|| Vec::<String>::new());
    let mut last_konami_time = use_signal(|| std::time::Instant::now());

    // Auto-focus the wrapper div on mount so keydown events fire immediately.
    use_effect(move || {
        spawn(async move {
            let _ = document::eval(
                r#"
                let el = document.querySelector('[data-shortcut-root]');
                if (el) el.focus();
                "#,
            )
            .await;
        });
    });

    let help_visible = props.help_visible;
    let chat_visible = props.chat_visible;

    rsx! {
        div {
            "data-shortcut-root": "true",
            tabindex: 0,
            style: "outline: none; display: contents;",
            onkeydown: move |evt: Event<KeyboardData>| {
                let key = evt.key();
                let ctrl_key = evt.modifiers().ctrl();
                let shift_key = evt.modifiers().shift();

                // --- Konami Code Detection ---
                if let Some(on_konami) = &props.on_konami {
                    let now = std::time::Instant::now();
                    let mut seq = konami_sequence.write();

                    // Reset if more than 2 seconds since last key
                    if now.duration_since(*last_konami_time.read()) > std::time::Duration::from_secs(2) {
                        seq.clear();
                    }
                    last_konami_time.set(now);

                    // Add key to sequence
                    let key_str = key.to_string();
                    seq.push(key_str.clone());

                    tracing::debug!("Konami: key={}, sequence len={}", key_str, seq.len());

                    // Keep only last 10 keys
                    if seq.len() > 10 {
                        seq.remove(0);
                    }

                    // Check if sequence matches Konami code
                    if seq.len() == KONAMI_SEQUENCE.len() {
                        let matches = seq.iter().zip(KONAMI_SEQUENCE.iter()).all(|(a, b)| {
                            let a_lower = a.to_lowercase();
                            let b_lower = b.to_lowercase();
                            a_lower == b_lower
                        });

                        if matches {
                            tracing::info!("Konami code activated!");
                            seq.clear();
                            on_konami.call(());
                            return; // Don't process other shortcuts
                        }
                    }
                }

                // --- Ctrl+Shift+1-8: Theme switching ---
                if ctrl_key && shift_key {
                    if let Some(on_theme_change) = &props.on_theme_change {
                        let theme_opt = match key {
                            Key::Character(ref c) => match c.as_str() {
                                "1" => Some(Theme::Dark),
                                "2" => Some(Theme::Light),
                                "3" => Some(Theme::Dracula),
                                "4" => Some(Theme::Gruvbox),
                                "5" => Some(Theme::TokyoNight),
                                "6" => Some(Theme::Matrix),
                                "7" => Some(Theme::Cyberpunk),
                                "8" => Some(Theme::Nord),
                                _ => None,
                            },
                            _ => None,
                        };

                        if let Some(theme) = theme_opt {
                            on_theme_change.call(theme);
                            return;
                        }
                    }
                }

                // --- Escape: close help first, then chat ---
                if key == Key::Escape {
                    if help_visible {
                        props.on_close_help.call(());
                    } else if chat_visible {
                        props.on_close_chat.call(());
                    }
                    return;
                }

                // Ignore remaining shortcuts when an editable element is focused.
                // We check via a synchronous heuristic: if the key is a character
                // key and the browser focus is inside an input/textarea/select,
                // the keydown event will have already been consumed by that element.
                // However, Dioxus div-level handlers still see it, so we use JS
                // to detect the active element tag.
                //
                // Because `document::eval` is async and we cannot await inside
                // the synchronous event handler, we use a spawn + eval pattern
                // that posts the key to a second handler.  For simplicity and
                // reliability we instead embed a tiny JS shim that checks
                // `document.activeElement.tagName` and sets a global flag.
                //
                // Practical workaround: we filter by Key enum variant.  Number
                // and letter keys typed into inputs will propagate up, but the
                // underlying input will also receive them.  We check via eval.

                // For single-char shortcuts, schedule an async check.
                let on_navigate = props.on_navigate;
                let on_toggle_help = props.on_toggle_help;

                // Map keys to actions
                let action: Option<ShortcutAction> = match key {
                    Key::Character(ref c) => match c.as_str() {
                        "?" => Some(ShortcutAction::ToggleHelp),
                        "1" => Some(ShortcutAction::Navigate(NavPage::Dashboard)),
                        "2" => Some(ShortcutAction::Navigate(NavPage::Tools)),
                        "3" => Some(ShortcutAction::Navigate(NavPage::Files)),
                        "4" => Some(ShortcutAction::Navigate(NavPage::Shell)),
                        "5" => Some(ShortcutAction::Navigate(NavPage::Logs)),
                        "6" => Some(ShortcutAction::Navigate(NavPage::Settings)),
                        "c" | "C" => Some(ShortcutAction::Navigate(NavPage::Chat)),
                        _ => None,
                    },
                    _ => None,
                };

                if let Some(action) = action {
                    // Spawn async task to check activeElement before dispatching
                    spawn(async move {
                        // Check if focus is in an editable element
                        let should_skip = match document::eval(
                            r#"
                            var tag = document.activeElement ? document.activeElement.tagName : '';
                            var editable = document.activeElement && document.activeElement.isContentEditable;
                            return (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || editable);
                            "#,
                        ).await {
                            Ok(val) => val.as_bool().unwrap_or(false),
                            Err(_) => false,
                        };

                        if should_skip {
                            return;
                        }

                        match action {
                            ShortcutAction::ToggleHelp => on_toggle_help.call(()),
                            ShortcutAction::Navigate(page) => on_navigate.call(page),
                        }
                    });
                }
            },
            {props.children}
        }
    }
}

/// Internal enum to pass shortcut intent across the async boundary.
#[derive(Clone, Copy)]
enum ShortcutAction {
    ToggleHelp,
    Navigate(NavPage),
}
