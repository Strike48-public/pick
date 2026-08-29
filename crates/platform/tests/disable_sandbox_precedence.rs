//! Regression guard for #244 Problem 1: `DISABLE_SANDBOX` must take precedence
//! over the UI shell-mode toggle. Once the environment has disabled the
//! sandbox, `set_use_sandbox(true)` (driven by the desktop/web shell-mode
//! setting) is a no-op and `is_sandbox_enabled()` stays `false`.
//!
//! This is pure in-memory logic (an env var plus process-global atomics): it
//! provisions no rootfs, spawns no backend, and touches no network. Unlike the
//! backend harnesses in this directory it is therefore NOT `#[ignore]`d and
//! runs in the required CI job (`cargo test --workspace ... --features
//! pentest-platform/desktop-pcap`, which also sets `DISABLE_SANDBOX=true`).
//!
//! It lives in its own integration binary on purpose: `init_sandbox_from_env`
//! reads `DISABLE_SANDBOX` exactly once via `std::sync::Once`, so the env var
//! must be set before anything else in the process touches the sandbox API.
//! A dedicated single-test binary guarantees that ordering.
//!
//! Desktop-gated: the real `set_use_sandbox` / `is_sandbox_enabled` live in
//! `pentest_platform::desktop`; on non-desktop feature builds the crate root
//! exposes no-op stubs, so there is no precedence to guard there.
#![cfg(feature = "desktop")]

#[test]
fn env_disable_wins_over_ui_shell_mode_toggle() {
    // Set before the first sandbox call so the `init_sandbox_from_env` `Once`
    // latches the env-disabled state. Safe on edition 2021.
    std::env::set_var("DISABLE_SANDBOX", "true");

    // The env has disabled the sandbox: it reports off.
    assert!(
        !pentest_platform::is_sandbox_enabled(),
        "DISABLE_SANDBOX=true must report the sandbox disabled"
    );

    // The UI shell-mode toggle tries to switch it back on. The env wins, so
    // this is a no-op and the sandbox stays off.
    pentest_platform::set_use_sandbox(true);
    assert!(
        !pentest_platform::is_sandbox_enabled(),
        "set_use_sandbox(true) must not override DISABLE_SANDBOX=true"
    );

    // An explicit shell-mode "off" is consistent and also leaves it off.
    pentest_platform::set_use_sandbox(false);
    assert!(
        !pentest_platform::is_sandbox_enabled(),
        "sandbox must remain disabled after set_use_sandbox(false)"
    );
}
