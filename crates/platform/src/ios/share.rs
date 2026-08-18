//! Present the iOS share sheet (UIActivityViewController) for text/URLs.

use objc2::rc::Retained;
use objc2::runtime::AnyObject;
use objc2::{class, msg_send, MainThreadMarker};
use objc2_core_foundation::{CGPoint, CGRect, CGSize};
use objc2_foundation::{NSArray, NSString};
use objc2_ui_kit::{UIApplication, UIWindow};
use pentest_core::error::Result;

/// Present a share sheet for `text`. Runs on the main thread.
pub fn share_text(text: &str) -> Result<()> {
    let text = text.to_string();
    crate::ios::dispatch_on_main(move || {
        // SAFETY: main-thread UIKit; standard UIActivityViewController flow.
        let mtm = unsafe { MainThreadMarker::new_unchecked() };
        let ns = NSString::from_str(&text);
        let items: Retained<NSArray<NSString>> = NSArray::from_retained_slice(&[ns]);
        unsafe {
            let alloc: *mut AnyObject = msg_send![class!(UIActivityViewController), alloc];
            let vc: *mut AnyObject = msg_send![
                alloc,
                initWithActivityItems: &*items,
                applicationActivities: std::ptr::null::<AnyObject>()
            ];

            // Find the key window to present from
            let app = UIApplication::sharedApplication(mtm);
            let windows: Retained<NSArray<UIWindow>> = msg_send![&app, windows];

            if windows.count() > 0 {
                // Walk windows for the key one; fall back to the first
                let mut key_window: Option<Retained<UIWindow>> = None;
                for i in 0..windows.count() {
                    let w = windows.objectAtIndex(i);
                    let is_key: bool = msg_send![&w, isKeyWindow];
                    if is_key {
                        key_window = Some(w);
                        break;
                    }
                }

                let win = key_window.unwrap_or_else(|| windows.objectAtIndex(0));
                let root: *mut AnyObject = msg_send![&win, rootViewController];

                if !root.is_null() {
                    // On iPad, UIActivityViewController requires a popoverPresentationController
                    // sourceView to avoid a crash. Set it to the root view with a small rect.
                    let popover: *mut AnyObject = msg_send![vc, popoverPresentationController];
                    if !popover.is_null() {
                        let root_view: *mut AnyObject = msg_send![root, view];
                        if !root_view.is_null() {
                            let _: () = msg_send![popover, setSourceView: root_view];
                            // Set a small sourceRect at origin (0,0) with size (1,1)
                            let rect = CGRect::new(CGPoint::new(0.0, 0.0), CGSize::new(1.0, 1.0));
                            let _: () = msg_send![popover, setSourceRect: rect];
                        }
                    }

                    let _: () = msg_send![
                        root,
                        presentViewController: vc,
                        animated: true,
                        completion: std::ptr::null::<std::ffi::c_void>()
                    ];
                }
            }
        }
    });
    Ok(())
}
