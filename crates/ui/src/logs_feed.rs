//! Dioxus side of the shared Logs buffer ([`pentest_core::ui_log`]).

use dioxus::prelude::*;
use pentest_core::terminal::TerminalLine;
use pentest_core::ui_log::{self, UI_LOG_CAPACITY};

/// The Logs lines for one page: the buffer as it is at mount, then each new
/// line as it is pushed.
///
/// The page owns the returned signal, so clearing it clears this page only,
/// and the clear sticks: updates append the lines numbered after the last one
/// this page took, never the whole buffer again.
pub fn use_ui_log_lines() -> Signal<Vec<TerminalLine>> {
    let (mut lines, mut seen) = use_hook(|| {
        let (initial, seq) = ui_log::global().since(0);
        (Signal::new(initial), Signal::new(seq))
    });
    use_future(move || async move {
        let log = ui_log::global();
        // Subscribed before reading, so a push between the two still wakes us.
        let mut changes = log.subscribe();
        loop {
            let (new, last) = log.since(*seen.peek());
            seen.set(last);
            if !new.is_empty() {
                let mut lines = lines.write();
                lines.extend(new);
                let excess = lines.len().saturating_sub(UI_LOG_CAPACITY);
                lines.drain(..excess);
            }
            if changes.changed().await.is_err() {
                return;
            }
        }
    });
    lines
}
