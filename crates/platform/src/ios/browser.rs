//! Open a URL in the system browser (Safari) via
//! `UIApplication.openURL:options:completionHandler:`.
//!
//! Unlike the OAuth flow (which needs an in-app ASWebAuthenticationSession to
//! keep a loopback callback alive), plain "open this report page" just launches
//! Safari. Runs on the main thread.
//!
//! NOTE: the legacy `openURL:` selector is deprecated and a silent no-op on
//! modern iOS (10+), so we must use the options+completionHandler variant.

use objc2::rc::Retained;
use objc2::runtime::AnyObject;
use objc2::{msg_send, MainThreadMarker};
use objc2_foundation::{NSDictionary, NSString, NSURL};
use objc2_ui_kit::UIApplication;
use pentest_core::error::Result;

/// Open `url` in the system browser. The open is dispatched to the main
/// queue fire-and-forget; a malformed URL is silently ignored.
pub fn open_url(url: &str) -> Result<()> {
    let url = url.to_string();
    crate::ios::dispatch_on_main(move || {
        // SAFETY: on the main queue; standard UIApplication open-URL call.
        let mtm = unsafe { MainThreadMarker::new_unchecked() };
        let ns = NSString::from_str(&url);
        if let Some(ns_url) = NSURL::URLWithString(&ns) {
            let app = UIApplication::sharedApplication(mtm);
            // Empty options dictionary; null completion handler.
            let options: Retained<NSDictionary> = NSDictionary::new();
            // SAFETY: openURL:options:completionHandler: is the modern opener;
            // the legacy openURL: is a no-op on iOS 10+. Completion handler is
            // an optional block, so a null pointer is valid.
            let _: () = unsafe {
                msg_send![
                    &app,
                    openURL: &*ns_url,
                    options: &*options,
                    completionHandler: std::ptr::null::<AnyObject>(),
                ]
            };
        }
    });
    // Dispatched asynchronously; assume success (matches Android opener contract).
    Ok(())
}
