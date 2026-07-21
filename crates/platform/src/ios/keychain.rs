//! iOS Keychain-backed secure storage for the Matrix chat token.
//!
//! Wraps the Security framework `SecItem*` C API. Items are stored as
//! `kSecClassGenericPassword` under a fixed service, `accessible` only after
//! first unlock on this device (never synced to iCloud, never leaves the
//! device). Registered into `pentest_core::secure_store` at startup so the UI
//! persists/restores the token without any plaintext on disk.

use objc2::runtime::AnyObject;
use objc2_foundation::{NSData, NSDictionary, NSString};
use std::ffi::c_void;

// Security.framework C API + the CF constants we key the query with.
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
}

const SERVICE: &str = "io.strike48.pick.chat";
const ERR_SEC_SUCCESS: i32 = 0;
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
const ERR_SEC_DUPLICATE_ITEM: i32 = -25299;

/// A CF pointer (`*const c_void`) usable as an NSDictionary value. NSString and
/// NSData are toll-free bridged to CFString/CFData, and the `kSec*` globals are
/// CFTypeRef — so we can build the query as an NSDictionary and pass it as
/// CFDictionaryRef to the SecItem* calls.
fn cf(ptr: *const c_void) -> *mut AnyObject {
    ptr as *mut AnyObject
}

/// Build the base query dict (class + service + account) shared by all ops.
fn base_query(account: &str) -> objc2::rc::Retained<NSDictionary> {
    let account = NSString::from_str(account);
    // SAFETY: kSec* are valid CFTypeRefs; NSString bridges to CFString.
    unsafe {
        let keys: [*mut AnyObject; 3] = [cf(kSecClass), cf(kSecAttrService), cf(kSecAttrAccount)];
        let vals: [*mut AnyObject; 3] = [
            cf(kSecClassGenericPassword),
            NSString::from_str(SERVICE).as_ref() as *const NSString as *mut AnyObject,
            account.as_ref() as *const NSString as *mut AnyObject,
        ];
        dict_from_raw(&keys, &vals)
    }
}

/// Construct an NSDictionary from raw (CF) key/value pointers. Kept unsafe and
/// local because these are toll-free-bridged CF objects, not ordinary objc2
/// types.
unsafe fn dict_from_raw(
    keys: &[*mut AnyObject],
    vals: &[*mut AnyObject],
) -> objc2::rc::Retained<NSDictionary> {
    use objc2::msg_send;
    let cls = objc2::class!(NSDictionary);
    let dict: objc2::rc::Retained<NSDictionary> = msg_send![
        cls,
        dictionaryWithObjects: vals.as_ptr(),
        forKeys: keys.as_ptr(),
        count: keys.len(),
    ];
    dict
}

/// Store (upsert) a secret. Deletes any existing item first so add always
/// succeeds with the fresh value.
pub fn set(account: &str, value: &str) -> Result<(), String> {
    let _ = delete(account); // ignore not-found

    let data = NSData::with_bytes(value.as_bytes());
    // SAFETY: building a CFDictionary of CFTypeRefs for SecItemAdd.
    let attrs = unsafe {
        let keys: [*mut AnyObject; 5] = [
            cf(kSecClass),
            cf(kSecAttrService),
            cf(kSecAttrAccount),
            cf(kSecValueData),
            cf(kSecAttrAccessible),
        ];
        let acct = NSString::from_str(account);
        let vals: [*mut AnyObject; 5] = [
            cf(kSecClassGenericPassword),
            NSString::from_str(SERVICE).as_ref() as *const NSString as *mut AnyObject,
            acct.as_ref() as *const NSString as *mut AnyObject,
            data.as_ref() as *const NSData as *mut AnyObject,
            cf(kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly),
        ];
        dict_from_raw(&keys, &vals)
    };

    let status = unsafe {
        SecItemAdd(
            objc2::rc::Retained::as_ptr(&attrs) as *const c_void,
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
    let query = base_query(account);
    // Augment with return-data + match-limit-one.
    // SAFETY: appending CF constants to a mutable copy of the base query.
    let full = unsafe {
        use objc2::msg_send;
        let m: objc2::rc::Retained<objc2_foundation::NSMutableDictionary> =
            msg_send![&*query, mutableCopy];
        let _: () = msg_send![&m, setObject: cf(kSecReturnData), forKey: cf(kSecReturnData)];
        // return-data value is kCFBooleanTrue; use match-limit-one for the limit.
        let _: () = msg_send![&m, setObject: cf(kSecMatchLimitOne), forKey: cf(kSecMatchLimit)];
        m
    };

    let mut result: *const c_void = std::ptr::null();
    let status = unsafe {
        SecItemCopyMatching(
            objc2::rc::Retained::as_ptr(&full) as *const c_void,
            &mut result as *mut *const c_void,
        )
    };
    match status {
        ERR_SEC_SUCCESS if !result.is_null() => {
            // result is a CFDataRef (toll-free bridged to NSData).
            let data: &NSData = unsafe { &*(result as *const NSData) };
            let bytes = data.to_vec();
            String::from_utf8(bytes)
                .map(Some)
                .map_err(|e| format!("Keychain value not UTF-8: {e}"))
        }
        ERR_SEC_ITEM_NOT_FOUND => Ok(None),
        s => Err(format!("Keychain SecItemCopyMatching failed: {s}")),
    }
}

/// Delete a secret. Not-found is treated as success (idempotent).
pub fn delete(account: &str) -> Result<(), String> {
    let query = base_query(account);
    let status = unsafe {
        SecItemDelete(objc2::rc::Retained::as_ptr(&query) as *const c_void)
    };
    match status {
        ERR_SEC_SUCCESS | ERR_SEC_ITEM_NOT_FOUND => Ok(()),
        s => Err(format!("Keychain SecItemDelete failed: {s}")),
    }
}
