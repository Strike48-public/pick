//! `workspace_confining_sandbox` is the probe Pick's connector reads before it
//! advertises engagement isolation (pick#513). It must fail closed: with the
//! sandbox off, commands run on the host, so no backend may be reported.
//!
//! This exercises the real crate-root probe and the desktop backend lookup
//! behind it, not a stub. It lives in its own integration binary because it
//! sets the process-global sandbox flag, which would race other tests in a
//! shared binary. The path that reports a backend needs an initialized
//! sandbox manager (a real bwrap, proot or Docker backend), so it is not
//! covered here; `confining` in `desktop::sandbox` has the unit test for the
//! enabled-and-confining rule.
#![cfg(feature = "desktop")]

#[test]
fn a_disabled_sandbox_reports_no_confining_backend() {
    pentest_platform::set_use_sandbox(false);
    assert!(!pentest_platform::is_sandbox_enabled());

    assert_eq!(pentest_platform::workspace_confining_sandbox(), None);
}
