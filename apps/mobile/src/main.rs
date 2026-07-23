//! Pentest Connector Mobile Application Entry Point

use dioxus::prelude::*;

use pentest_core::config::ShellMode;
use pentest_ui::{connector_app, ConnectorAppConfig};

const MOBILE_CONFIG: ConnectorAppConfig = ConnectorAppConfig {
    platform_name: "Mobile",
    container_class: "app-container",
    shell_route_mode: ShellMode::Proot,
    default_proot: true,
    start_liveview_server: true,
    inject_css: true,
    extra_init_messages: &[],
    create_tools: pentest_tools::create_tool_registry,
    set_sandbox: None,
    easy_mode: true,
};

fn main() {
    #[cfg(target_os = "android")]
    {
        android_logger::init_once(
            android_logger::Config::default()
                .with_max_level(log::LevelFilter::Debug)
                .with_tag("PentestConnector"),
        );

        // Dev-only: propagate the BUILD-TIME baked MATRIX_TLS_INSECURE into the
        // process env so the strike48-connector SDK — which reads it via
        // std::env::var when it builds its WebSocket/gRPC/OTT HTTP clients — can
        // see it. Mobile apps have no runtime environment, so without this the
        // SDK's register-with-ott call verify-fails against the local mkcert dev
        // cluster ("error sending request"), even though our own baked reqwest
        // clients (GraphQL, pre-approve) succeed. `option_env!` is None in a
        // release build that didn't set it, so this is a no-op in production and
        // cannot ship an insecure default.
        if let Some(v) = option_env!("MATRIX_TLS_INSECURE") {
            if !v.is_empty() && std::env::var_os("MATRIX_TLS_INSECURE").is_none() {
                std::env::set_var("MATRIX_TLS_INSECURE", v);
            }
        }

        pentest_platform::android::init();

        // Register Android-specific browser opener for OAuth flows
        pentest_core::matrix::set_browser_opener(|url| {
            pentest_platform::android::open_browser(url).map_err(|e| e.to_string())
        });

        // Register share handler
        pentest_core::share::set_share_handler(|text| {
            pentest_platform::android::share_text(text).map_err(|e| e.to_string())
        });

        // Secure token storage via Android EncryptedSharedPreferences (Keystore).
        pentest_core::secure_store::set_backend(
            |k, v| pentest_platform::android::secure_set(k, v).map_err(|e| e.to_string()),
            |k| pentest_platform::android::secure_get(k).map_err(|e| e.to_string()),
            |k| pentest_platform::android::secure_delete(k).map_err(|e| e.to_string()),
        );

        // Native OAuth: OAuthCallbackActivity delivers the token straight into
        // the core via the JNI export in this lib (see the
        // Java_..._OAuthCallbackActivity_deliverOAuthToken symbol below), so no
        // loopback callback server or port hand-off is needed on Android.
    }

    #[cfg(target_os = "ios")]
    {
        // Register the iOS native OIDC session (ASWebAuthenticationSession).
        // The loopback-callback flow can't work on iOS — launching a browser
        // backgrounds the app and suspends the callback server — so iOS uses
        // this in-app auth session with a custom-scheme callback instead. It's
        // the iOS analog of Android's OAuthCallbackActivity. The callback scheme
        // (com.strike48.pentest) is declared in the Info.plist via Dioxus.toml.
        pentest_core::matrix::set_web_auth_session(|url, scheme| {
            pentest_platform::ios::present_web_auth_session(url, scheme).map_err(|e| e.to_string())
        });

        // Secure token storage via the iOS Keychain (so the chat token survives
        // relaunch without any plaintext on disk).
        pentest_core::secure_store::set_backend(
            |k, v| pentest_platform::ios::keychain::set(k, v),
            |k| pentest_platform::ios::keychain::get(k),
            |k| pentest_platform::ios::keychain::delete(k),
        );

        // Register iOS browser opener for opening report URLs
        pentest_core::matrix::set_browser_opener(|url| {
            pentest_platform::ios::open_url(url).map_err(|e| e.to_string())
        });

        // Register share handler
        pentest_core::share::set_share_handler(|text| {
            pentest_platform::ios::share_text(text).map_err(|e| e.to_string())
        });
    }

    dioxus::launch(MobileApp);
}

#[component]
fn MobileApp() -> Element {
    connector_app(MOBILE_CONFIG)
}

/// JNI entrypoint: `OAuthCallbackActivity` calls this with the full
/// custom-scheme callback URL (`com.strike48.pentest://oauth/callback?...`)
/// after the OS routes the browser's OAuth redirect back to the app. We hand it
/// to the core, which parses the `access_token` and completes the in-flight
/// login. This replaces the loopback HTTP hand-off, which can't work on Android
/// (launching the browser backgrounds the app and suspends the callback
/// server).
///
/// The JNI symbol encodes the Kotlin package: the `_` in `pentest_connector`
/// mangles to `_1`. Runs on the JVM thread — we only send on a channel, so no
/// thread affinity is required.
///
/// # Safety
/// Standard JNI ABI contract: `env`/`url` are valid handles supplied by the JVM.
#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_com_strike48_pentest_1connector_OAuthCallbackActivity_deliverOAuthToken(
    mut env: jni::JNIEnv,
    _class: jni::objects::JClass,
    url: jni::objects::JString,
) -> jni::sys::jboolean {
    let callback_url = match env.get_string(&url) {
        Ok(s) => String::from(s),
        Err(e) => {
            tracing::error!("deliverOAuthToken: failed to read callback URL: {e}");
            return false as jni::sys::jboolean;
        }
    };
    pentest_core::matrix::deliver_native_oauth_callback(&callback_url) as jni::sys::jboolean
}
