//! Open a URL in the system browser (Safari) via `UIApplication.openURL:`.
//!
//! Unlike the OAuth flow (which needs an in-app ASWebAuthenticationSession to
//! keep a loopback callback alive), plain "open this report page" just launches
//! Safari. Runs on the main thread.

use objc2::{msg_send, MainThreadMarker};
use objc2_foundation::{NSString, NSURL};
use objc2_ui_kit::UIApplication;
use pentest_core::error::Result;

/// Open `url` in the system browser. The open is dispatched to the main
/// queue fire-and-forget; a malformed URL is silently ignored.
pub fn open_url(url: &str) -> Result<()> {
    let url = url.to_string();
    crate::ios::dispatch_on_main(move || {
        // SAFETY: on the main queue; standard UIApplication.openURL call.
        let mtm = unsafe { MainThreadMarker::new_unchecked() };
        let ns = NSString::from_str(&url);
        if let Some(ns_url) = NSURL::URLWithString(&ns) {
            let app = UIApplication::sharedApplication(mtm);
            // SAFETY: openURL: is the legacy opener (simpler than openURL:options:completionHandler:).
            // Returns bool indicating whether the URL scheme can be opened.
            let _: bool = unsafe { msg_send![&app, openURL: &*ns_url] };
        }
    });
    // Dispatched asynchronously; assume success (matches Android opener contract).
    Ok(())
}
