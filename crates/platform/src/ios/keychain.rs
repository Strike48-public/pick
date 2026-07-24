//! iOS Keychain-backed secure storage for the Matrix chat token.
//!
//! Wraps the Security framework `SecItem*` C API. Items are stored as
//! `kSecClassGenericPassword` under a fixed service, accessible only after
//! first unlock on this device (never synced to iCloud, never leaves the
//! device). Registered into `pentest_core::secure_store` at startup so the UI
//! persists/restores the token without any plaintext on disk.
//!
//! Dictionaries are built with `NSMutableDictionary` and objc2's typed
//! `setObject:forKey:` — every value is held in a live `Retained` binding until
//! after the SecItem call, so nothing dangles. NSString/NSData are toll-free
//! bridged to CFString/CFData, and the `kSec*` globals are CFTypeRefs, so an
//! NSDictionary passes straight to the CFDictionaryRef-typed SecItem functions.

use objc2::msg_send;
use objc2::rc::Retained;
use objc2::runtime::AnyObject;
use objc2_foundation::{NSData, NSMutableDictionary, NSString};
use std::ffi::c_void;

#[link(name = "Security", kind = "framework")]
extern "C" {
    fn SecItemAdd(attributes: *const c_void, result: *mut *const c_void) -> i32;
    fn SecItemCopyMatching(query: *const c_void, result: *mut *const c_void) -> i32;
    fn SecItemDelete(query: *const c_void) -> i32;

    static kSecClass: *const c_void;
    static kSecClassGenericPassword: *const c_void;
    static kSecAttrService: *const c_void;
    static kSecAttrAccount: *const c_void;
    static kSecValueData: *const c_void;
    static kSecReturnData: *const c_void;
    static kSecMatchLimit: *const c_void;
    static kSecMatchLimitOne: *const c_void;
    static kSecAttrAccessible: *const c_void;
    static kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly: *const c_void;
    // CFBoolean true, used as the kSecReturnData value.
    static kCFBooleanTrue: *const c_void;
}

const SERVICE: &str = "io.strike48.pick.chat";
const ERR_SEC_SUCCESS: i32 = 0;
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
const ERR_SEC_DUPLICATE_ITEM: i32 = -25299;

/// A CF constant pointer viewed as an objc object (for use as a dict key/value).
#[inline]
fn cf(ptr: *const c_void) -> *const AnyObject {
    ptr as *const AnyObject
}

/// Set `key => value` on a mutable dict. `key` and `value` are borrowed for the
/// duration of the call, so the caller must keep any `Retained` alive.
///
/// # Safety
/// `key`/`value` must be valid, retained objc/CF objects.
unsafe fn put(dict: &NSMutableDictionary, value: *const AnyObject, key: *const AnyObject) {
    let _: () = msg_send![dict, setObject: value, forKey: key];
}

/// Run `SecItemDelete` for `account`. Not-found is success (idempotent).
pub fn delete(account: &str) -> Result<(), String> {
    // Hold every value in a binding so nothing is dropped before the call.
    let service = NSString::from_str(SERVICE);
    let acct = NSString::from_str(account);
    let query = NSMutableDictionary::new();
    // SAFETY: all keys/values are live retained CF/objc objects; NSDictionary
    // is passed to the CFDictionaryRef-typed SecItemDelete.
    let status = unsafe {
        put(&query, cf(kSecClassGenericPassword), cf(kSecClass));
        put(
            &query,
            &*service as *const NSString as *const AnyObject,
            cf(kSecAttrService),
        );
        put(
            &query,
            &*acct as *const NSString as *const AnyObject,
            cf(kSecAttrAccount),
        );
        SecItemDelete(Retained::as_ptr(&query) as *const c_void)
    };
    match status {
        ERR_SEC_SUCCESS | ERR_SEC_ITEM_NOT_FOUND => Ok(()),
        s => Err(format!("Keychain SecItemDelete failed: {s}")),
    }
}

/// Store (upsert) a secret: delete any existing item, then add the fresh value.
pub fn set(account: &str, value: &str) -> Result<(), String> {
    let _ = delete(account);

    let service = NSString::from_str(SERVICE);
    let acct = NSString::from_str(account);
    let data = NSData::with_bytes(value.as_bytes());
    let attrs = NSMutableDictionary::new();
    // SAFETY: every value below is a live retained CF/objc object held in a
    // binding until after SecItemAdd; NSDictionary → CFDictionaryRef.
    let status = unsafe {
        put(&attrs, cf(kSecClassGenericPassword), cf(kSecClass));
        put(
            &attrs,
            &*service as *const NSString as *const AnyObject,
            cf(kSecAttrService),
        );
        put(
            &attrs,
            &*acct as *const NSString as *const AnyObject,
            cf(kSecAttrAccount),
        );
        put(
            &attrs,
            &*data as *const NSData as *const AnyObject,
            cf(kSecValueData),
        );
        put(
            &attrs,
            cf(kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly),
            cf(kSecAttrAccessible),
        );
        SecItemAdd(
            Retained::as_ptr(&attrs) as *const c_void,
            std::ptr::null_mut(),
        )
    };
    match status {
        ERR_SEC_SUCCESS | ERR_SEC_DUPLICATE_ITEM => Ok(()),
        s => Err(format!("Keychain SecItemAdd failed: {s}")),
    }
}

/// Read a secret, or `None` if absent.
pub fn get(account: &str) -> Result<Option<String>, String> {
    let service = NSString::from_str(SERVICE);
    let acct = NSString::from_str(account);
    let query = NSMutableDictionary::new();
    let mut result: *const c_void = std::ptr::null();
    // SAFETY: live retained values; result receives a retained CFDataRef we
    // then read as NSData (toll-free bridged).
    let status = unsafe {
        put(&query, cf(kSecClassGenericPassword), cf(kSecClass));
        put(
            &query,
            &*service as *const NSString as *const AnyObject,
            cf(kSecAttrService),
        );
        put(
            &query,
            &*acct as *const NSString as *const AnyObject,
            cf(kSecAttrAccount),
        );
        put(&query, cf(kCFBooleanTrue), cf(kSecReturnData));
        put(&query, cf(kSecMatchLimitOne), cf(kSecMatchLimit));
        SecItemCopyMatching(
            Retained::as_ptr(&query) as *const c_void,
            &mut result as *mut *const c_void,
        )
    };
    match status {
        // SAFETY: on success with return-data, result is a retained CFDataRef
        // (toll-free bridged to NSData). `as_ref` null-checks the out-param
        // before forming a reference, so a null/invalid pointer is never
        // dereferenced (a missing item reads as `None`).
        ERR_SEC_SUCCESS => match unsafe { (result as *const NSData).as_ref() } {
            Some(data) => {
                let bytes = data.to_vec();
                String::from_utf8(bytes)
                    .map(Some)
                    .map_err(|e| format!("Keychain value not UTF-8: {e}"))
            }
            None => Ok(None),
        },
        ERR_SEC_ITEM_NOT_FOUND => Ok(None),
        s => Err(format!("Keychain SecItemCopyMatching failed: {s}")),
    }
}
