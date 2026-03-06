//! Android device enrichment via JNI (bd-22)
//!
//! Reads Build.VERSION.SDK_INT, Build.FINGERPRINT, PackageManager info,
//! and additional system properties to enrich the `extra` map inside
//! `PlatformDetails::Android`.

use super::jni_bridge::with_jni;
use crate::traits::{DeviceInfo, PlatformDetails};
use jni::objects::JValue;
use pentest_core::error::Result;

/// Return a mutable reference to the `extra` map when the platform is Android,
/// or `None` for any other variant.
fn android_extra(info: &mut DeviceInfo) -> Option<&mut std::collections::HashMap<String, String>> {
    match &mut info.platform_specific {
        PlatformDetails::Android { extra, .. } => Some(extra),
        _ => None,
    }
}

/// Enrich an existing DeviceInfo with Android-specific fields via JNI.
/// Failures are logged but not propagated — we merge what we can.
pub fn enrich(info: &mut DeviceInfo) {
    if let Err(e) = enrich_via_jni(info) {
        tracing::warn!("JNI device enrichment partial failure: {e}");
    }
    enrich_from_getprop(info, "ro.hardware", "hardware");
    enrich_from_getprop(info, "persist.sys.timezone", "timezone");
}

fn enrich_via_jni(info: &mut DeviceInfo) -> Result<()> {
    with_jni(|env, ctx| {
        // Build.VERSION.SDK_INT (static int field)
        if let Ok(cls) = env.find_class("android/os/Build$VERSION") {
            if let Ok(sdk) = env
                .get_static_field(&cls, "SDK_INT", "I")
                .and_then(|v| v.i())
            {
                if let Some(extra) = android_extra(info) {
                    extra.insert("api_level".into(), sdk.to_string());
                }
            }
        }

        // Build.FINGERPRINT (static String field)
        if let Ok(cls) = env.find_class("android/os/Build") {
            if let Ok(fp) = env
                .get_static_field(&cls, "FINGERPRINT", "Ljava/lang/String;")
                .and_then(|v| v.l())
            {
                let fp_str = super::jni_bridge::jstring_to_string(env, &fp);
                if !fp_str.is_empty() {
                    if let Some(extra) = android_extra(info) {
                        extra.insert("build_fingerprint".into(), fp_str);
                    }
                }
            }
        }

        // PackageManager.getInstalledPackages(0).size()
        let pm = env
            .call_method(
                ctx,
                "getPackageManager",
                "()Landroid/content/pm/PackageManager;",
                &[],
            )
            .and_then(|v| v.l());

        if let Ok(pm) = pm {
            if !pm.is_null() {
                let pkgs = env
                    .call_method(
                        &pm,
                        "getInstalledPackages",
                        "(I)Ljava/util/List;",
                        &[JValue::Int(0)],
                    )
                    .and_then(|v| v.l());

                if let Ok(pkgs) = pkgs {
                    if !pkgs.is_null() {
                        if let Ok(count) = env
                            .call_method(&pkgs, "size", "()I", &[])
                            .and_then(|v| v.i())
                        {
                            if let Some(extra) = android_extra(info) {
                                extra.insert("installed_package_count".into(), count.to_string());
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    })
}

/// Run getprop synchronously and insert the value into the `extra` map
/// if non-empty.
fn enrich_from_getprop(info: &mut DeviceInfo, prop: &str, key: &str) {
    if let Ok(output) = std::process::Command::new("getprop").arg(prop).output() {
        let val = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !val.is_empty() {
            if let Some(extra) = android_extra(info) {
                extra.insert(key.into(), val);
            }
        }
    }
}
