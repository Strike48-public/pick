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

use block2::RcBlock;
use objc2::rc::Retained;
use objc2::runtime::AnyObject;
use objc2::{define_class, msg_send, MainThreadOnly};
use objc2_authentication_services::ASWebAuthenticationSession;
use objc2_foundation::{MainThreadMarker, NSError, NSObject, NSObjectProtocol, NSString, NSURL};
use objc2_ui_kit::{UIApplication, UIWindow};
use pentest_core::error::{Error, Result};
use std::sync::mpsc;

define_class!(
    // A minimal main-thread object serving as the session's
    // ASWebAuthenticationPresentationContextProviding delegate. We declare the
    // `presentationAnchorForWebAuthenticationSession:` selector directly (via
    // raw #[method]) rather than `impl`ing the typed trait: the crate gates that
    // trait method to macOS and types the anchor as NSObject, which the typed
    // path can't encode as a method return. Returning a raw `*mut AnyObject`
    // pointer is a valid objc return and works on iOS.
    //
    // SAFETY:
    // - Superclass NSObject has no subclassing requirements.
    // - Does not implement Drop.
    #[unsafe(super = NSObject)]
    #[thread_kind = MainThreadOnly]
    #[name = "PickAuthPresentationContext"]
    struct PresentationContext;

    // SAFETY: NSObjectProtocol has no safety requirements.
    unsafe impl NSObjectProtocol for PresentationContext {}

    impl PresentationContext {
        // SAFETY: selector + signature match ASWebAuthenticationPresentation-
        // ContextProviding; returns the key window (an ASPresentationAnchor /
        // UIWindow) as a retained raw pointer the objc runtime can encode.
        #[unsafe(method(presentationAnchorForWebAuthenticationSession:))]
        fn presentation_anchor(&self, _session: &ASWebAuthenticationSession) -> *mut AnyObject {
            let window = key_window(self.mtm());
            // Hand ownership to the caller (objc +1 return convention for a
            // property-style getter is not expected here; the session does not
            // release it, so retain-and-leak the pointer).
            Retained::into_raw(window) as *mut AnyObject
        }
    }
);

impl PresentationContext {
    fn new(mtm: MainThreadMarker) -> Retained<Self> {
        // SAFETY: no ivars; NSObject's init is correct.
        unsafe { msg_send![Self::alloc(mtm), init] }
    }
}

/// The app's key window (an `ASPresentationAnchor` == `UIWindow` on iOS), to
/// anchor the auth session. Must run on the main thread.
fn key_window(mtm: MainThreadMarker) -> Retained<UIWindow> {
    let app = UIApplication::sharedApplication(mtm);
    // Walk windows for the key one; fall back to the first. Raw msg_send keeps
    // this tolerant of UIKit-binding shape across versions.
    // SAFETY: main-thread UIKit access; `windows` returns an NSArray<UIWindow>.
    unsafe {
        let windows: Retained<objc2_foundation::NSArray<UIWindow>> = msg_send![&app, windows];
        let count = windows.count();
        for i in 0..count {
            let w = windows.objectAtIndex(i);
            let is_key: bool = msg_send![&w, isKeyWindow];
            if is_key {
                return w;
            }
        }
        // No key window: return the first (still a valid anchor). If there are
        // somehow no windows, fall through to a freshly-made one.
        if count > 0 {
            return windows.objectAtIndex(0);
        }
        UIWindow::new(mtm)
    }
}

/// Present an `ASWebAuthenticationSession` for `url`, expecting the OAuth
/// provider to redirect to `<callback_scheme>://...`. Blocks until the session
/// completes (callback URL received) or errors, then returns the callback URL.
///
/// UIKit setup runs on the main thread; the completion is bridged back to this
/// (blocking-executor) thread via a channel.
pub fn present_web_auth_session(url: &str, callback_scheme: &str) -> Result<String> {
    let url = url.to_string();
    let callback_scheme = callback_scheme.to_string();
    let (tx, rx) = mpsc::channel::<std::result::Result<String, String>>();

    crate::ios::dispatch_on_main(move || {
        // MainThreadMarker is valid here: dispatch_on_main runs on the main queue.
        // SAFETY: we are on the main thread.
        let mtm = unsafe { MainThreadMarker::new_unchecked() };
        if let Err(e) = start_session(mtm, &url, &callback_scheme, tx.clone()) {
            let _ = tx.send(Err(e));
        }
    });

    match rx.recv() {
        Ok(Ok(callback_url)) => Ok(callback_url),
        Ok(Err(e)) => Err(Error::Matrix(format!("iOS web auth failed: {e}"))),
        Err(_) => Err(Error::Matrix(
            "iOS web auth session dropped before completion".into(),
        )),
    }
}

fn start_session(
    mtm: MainThreadMarker,
    url: &str,
    callback_scheme: &str,
    tx: mpsc::Sender<std::result::Result<String, String>>,
) -> std::result::Result<(), String> {
    let ns_url = NSString::from_str(url);
    // SAFETY: URLWithString returns nil for a malformed URL; checked.
    let auth_url = unsafe { NSURL::URLWithString(&ns_url) }
        .ok_or_else(|| format!("invalid auth URL: {url}"))?;
    let scheme = NSString::from_str(callback_scheme);

    // Completion handler block: (callbackURL, error).
    let handler = RcBlock::new(move |cb_url: *mut NSURL, err: *mut NSError| {
        // SAFETY: pointers are valid for the duration of the callback.
        unsafe {
            if !err.is_null() {
                let desc = (*err).localizedDescription();
                let _ = tx.send(Err(desc.to_string()));
                return;
            }
            if cb_url.is_null() {
                let _ = tx.send(Err("no callback URL and no error".to_string()));
                return;
            }
            let s: Retained<NSString> = msg_send![&*cb_url, absoluteString];
            let _ = tx.send(Ok(s.to_string()));
        }
    });

    // SAFETY: main-thread AuthenticationServices calls; objects kept alive below.
    let session = unsafe {
        // ASWebAuthenticationSession is not MainThreadOnly (AllocAnyThread), so
        // alloc() takes no marker. We're already on the main thread for start().
        ASWebAuthenticationSession::initWithURL_callbackURLScheme_completionHandler(
            ASWebAuthenticationSession::alloc(),
            &auth_url,
            Some(&scheme),
            RcBlock::as_ptr(&handler) as *mut _,
        )
    };

    let ctx = PresentationContext::new(mtm);
    // SAFETY: set the (weak) presentation-context provider via the raw selector
    // (the typed setter wants a ProtocolObject we intentionally don't construct)
    // and start the session.
    let started = unsafe {
        let _: () = msg_send![&session, setPresentationContextProvider: &*ctx];
        session.start()
    };
    if !started {
        return Err("ASWebAuthenticationSession.start() returned false".to_string());
    }

    // Keep session/delegate/handler alive until the block fires. The session
    // doesn't strongly retain its handler across the async boundary on all iOS
    // versions, and the context provider is a *weak* property — so leak them.
    // One-shot per app launch; memory is negligible.
    std::mem::forget(session);
    std::mem::forget(ctx);
    std::mem::forget(handler);
    Ok(())
}
