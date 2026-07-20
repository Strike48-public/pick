//! Native iOS OAuth via `ASWebAuthenticationSession`.
//!
//! The proper iOS OIDC flow. Unlike `UIApplication.openURL` (which launches
//! full Safari and *backgrounds* our app, suspending the loopback callback
//! server so the `http://localhost:<port>/callback` token relay never lands),
//! `ASWebAuthenticationSession` presents an in-app authentication browser that
//! keeps the app foregrounded and, on completion, hands the custom-scheme
//! callback URL (`com.strike48.pentest://oauth/callback?...`) straight to a
//! completion handler. No localhost server, no backgrounding.
//!
//! This is the iOS analog of Android's `OAuthCallbackActivity` intent filter.
//! The callback scheme must be declared in the app's Info.plist
//! `CFBundleURLTypes` (see `[ios.plist]` / `[ios].url_schemes` in Dioxus.toml).

use block2::RcBlock;
use objc2::rc::Retained;
use objc2::runtime::ProtocolObject;
use objc2::{define_class, msg_send, DefinedClass, MainThreadOnly};
use objc2_authentication_services::{
    ASPresentationAnchor, ASWebAuthenticationPresentationContextProviding,
    ASWebAuthenticationSession,
};
use objc2_foundation::{NSError, NSObject, NSObjectProtocol, NSString, NSURL};
use objc2_ui_kit::UIApplication;
use pentest_core::error::{Error, Result};
use std::sync::mpsc;

define_class!(
    // A minimal object conforming to ASWebAuthenticationPresentationContextProviding.
    // ASWebAuthenticationSession asks it for the window to anchor the auth
    // sheet to; we return the app's active key window.
    #[unsafe(super(NSObject))]
    #[name = "PickAuthPresentationContext"]
    struct PresentationContext;

    unsafe impl NSObjectProtocol for PresentationContext {}

    unsafe impl ASWebAuthenticationPresentationContextProviding for PresentationContext {
        #[unsafe(method(presentationAnchorForWebAuthenticationSession:))]
        unsafe fn presentation_anchor(
            &self,
            _session: &ASWebAuthenticationSession,
        ) -> Retained<ASPresentationAnchor> {
            // ASPresentationAnchor is a UIWindow on iOS. Return the app's key
            // window so the auth sheet has something to present over.
            key_window()
        }
    }
);

/// Find the app's active key window to anchor the auth session.
///
/// # Safety
/// Must be called on the main thread (UIKit requirement). Callers here invoke
/// it only from the main-thread session setup.
fn key_window() -> Retained<ASPresentationAnchor> {
    // SAFETY: on the main thread; walk connected scenes for a key window.
    unsafe {
        let mtm = objc2::MainThreadMarker::new_unchecked();
        let app = UIApplication::sharedApplication(mtm);
        // Prefer the keyWindow across connected scenes; fall back to the first
        // window. Use raw msg_send to stay version-tolerant across UIKit shapes.
        let windows: Retained<objc2_foundation::NSArray<objc2_ui_kit::UIWindow>> =
            msg_send![&app, windows];
        for i in 0..windows.count() {
            let w = windows.objectAtIndex(i);
            let is_key: bool = msg_send![&w, isKeyWindow];
            if is_key {
                return Retained::cast_unchecked(w);
            }
        }
        // No key window yet: return the first window (still a valid anchor).
        let first = windows.objectAtIndex(0);
        Retained::cast_unchecked(first)
    }
}

/// Present an `ASWebAuthenticationSession` for `url`, expecting the OAuth
/// provider to redirect to `<callback_scheme>://...`. Blocks until the session
/// completes (callback URL received) or is cancelled/errors, then returns the
/// full callback URL string.
///
/// Runs the UIKit session setup on the main thread and bridges the completion
/// back to this (async-executor) thread via a channel, so callers can `await`
/// it from `spawn_blocking`.
pub fn present_web_auth_session(url: &str, callback_scheme: &str) -> Result<String> {
    let url = url.to_string();
    let callback_scheme = callback_scheme.to_string();

    // Channel to carry the callback URL (or error) from the objc completion
    // block back to this thread.
    let (tx, rx) = mpsc::channel::<std::result::Result<String, String>>();

    // The session object is retained by holding it on the main thread for the
    // duration; we keep it alive via the delegate + a Box moved into the block.
    crate::ios::dispatch_on_main(move || {
        let result = start_session(&url, &callback_scheme, tx.clone());
        if let Err(e) = result {
            let _ = tx.send(Err(e));
        }
    });

    // Wait for the completion block to fire (ASWebAuthenticationSession has no
    // internal timeout; the caller in auth.rs wraps this in its own 120s bound
    // via spawn_blocking + the surrounding select).
    match rx.recv() {
        Ok(Ok(callback_url)) => Ok(callback_url),
        Ok(Err(e)) => Err(Error::Matrix(format!("iOS web auth failed: {e}"))),
        Err(_) => Err(Error::Matrix(
            "iOS web auth session dropped before completion".into(),
        )),
    }
}

/// Build, configure, and start the session. Must run on the main thread.
fn start_session(
    url: &str,
    callback_scheme: &str,
    tx: mpsc::Sender<std::result::Result<String, String>>,
) -> std::result::Result<(), String> {
    // SAFETY: main-thread UIKit/AuthServices calls; objects are retained for
    // the session lifetime (see the keep-alive note below).
    unsafe {
        let mtm = objc2::MainThreadMarker::new_unchecked();

        let ns_url = NSString::from_str(url);
        let auth_url =
            NSURL::URLWithString(&ns_url).ok_or_else(|| format!("invalid auth URL: {url}"))?;
        let scheme = NSString::from_str(callback_scheme);

        // Completion handler: (callbackURL, error). Send the outcome back.
        let handler = RcBlock::new(move |cb_url: *mut NSURL, err: *mut NSError| {
            if !err.is_null() {
                let e = &*err;
                let desc = e.localizedDescription();
                let _ = tx.send(Err(desc.to_string()));
                return;
            }
            if cb_url.is_null() {
                let _ = tx.send(Err("no callback URL and no error".to_string()));
                return;
            }
            let s: Retained<NSString> = msg_send![&*cb_url, absoluteString];
            let _ = tx.send(Ok(s.to_string()));
        });

        let session = ASWebAuthenticationSession::initWithURL_callbackURLScheme_completionHandler(
            ASWebAuthenticationSession::alloc(),
            &auth_url,
            Some(&scheme),
            RcBlock::as_ptr(&handler) as *mut _,
        );

        // Presentation context (required on iOS 13+ or -start returns false).
        let ctx = PresentationContext::new(mtm);
        let proto: &ProtocolObject<dyn ASWebAuthenticationPresentationContextProviding> =
            ProtocolObject::from_ref(&*ctx);
        session.setPresentationContextProvider(Some(proto));

        let started = session.start();
        if !started {
            return Err("ASWebAuthenticationSession.start() returned false".to_string());
        }

        // Keep the session, delegate, and handler alive until the block fires.
        // ASWebAuthenticationSession does not retain its own completion handler
        // strongly enough across the async boundary in all iOS versions, and the
        // presentation-context provider is a *weak* property — so leak them; the
        // flow is one-shot per app launch and the memory is negligible.
        std::mem::forget(session);
        std::mem::forget(ctx);
        std::mem::forget(handler);
    }
    Ok(())
}

impl PresentationContext {
    fn new(mtm: objc2::MainThreadMarker) -> Retained<Self> {
        // SAFETY: PresentationContext has no ivars; plain alloc/init.
        unsafe { msg_send![Self::alloc(mtm), init] }
    }
}
