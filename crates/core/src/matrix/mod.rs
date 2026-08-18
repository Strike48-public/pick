//! Matrix GraphQL client for agent chat integration.
//!
//! Provides a trait-based abstraction (`ChatClient`) so the backend
//! can be swapped without touching UI code.

mod agent_defaults;
mod auth;
pub mod chat_notice;
mod client;
pub mod documents;
pub mod phoenix_sub;
pub mod pre_approval;
pub mod report_meta;
pub mod stream_apply;
pub mod subscription;
mod types;

pub use agent_defaults::default_pentest_agent_input;
pub use auth::*;
pub use chat_notice::{build_error_notice, studio_url_from_api, ChatNotice, ChatNoticeKind};
pub use client::MatrixChatClient;
pub use documents::{latest_document, preview_url, DocumentSummary};
pub use phoenix_sub::{
    build_ws_url, create_heartbeat, create_join, create_subscription, extract_event, parse_event,
    ConversationStreamEvent, CONVERSATION_EVENTS_SUBSCRIPTION,
};
pub use pre_approval::{
    clear_staged_ott, pre_approve, stage_ott_for_sdk, staged_ott_path, OttData,
};
pub use report_meta::{BadgeKind, ReportFinding, ReportMeta, SeverityBadge, SeverityCounts};
pub use stream_apply::{apply_event, ApplyOutcome};
pub use subscription::{
    subscribe_conversation, AbortOnDrop, ConnectionState, ConversationSubscription,
};
pub use types::*;

/// Strip trailing slashes from a URL.
pub(crate) fn normalize_url(url: &str) -> &str {
    url.trim_end_matches('/')
}

/// Whether to skip TLS cert verification (DEV ONLY, for the local mkcert dev
/// cluster's self-signed chain). In DEBUG builds it is resolved at BUILD time
/// via `option_env!` first — the only source that reaches the mobile apps, which
/// have no runtime environment — then the RUNTIME env for desktop/dev/headless.
/// reqwest uses OpenSSL, which does NOT consult Android's system trust store, so
/// a device CA install can't help it; this flag is the dev path.
///
/// The build-time `option_env!` bake is gated to `#[cfg(debug_assertions)]`:
/// baking cert-skip into a RELEASE binary would ship a connector that
/// permanently trusts forged certs with no runtime override — a standing MITM
/// exposure of the bearer token/OTT. Release builds honor ONLY the runtime env
/// (which an operator sets deliberately), so a release build never silently
/// trusts bad certs just because it was compiled in an insecure-dev environment.
///
/// Shared by every reqwest client in this module (GraphQL, pre-approval) so they
/// resolve TLS trust identically — a per-client copy that read only the runtime
/// env would silently verify-fail on mobile, where that env is always empty.
pub(crate) fn insecure_tls() -> bool {
    let truthy = |v: &str| v == "1" || v == "true";
    #[cfg(debug_assertions)]
    if let Some(v) = option_env!("MATRIX_TLS_INSECURE").or(option_env!("MATRIX_INSECURE")) {
        if truthy(v) {
            return true;
        }
    }
    std::env::var("MATRIX_TLS_INSECURE")
        .or_else(|_| std::env::var("MATRIX_INSECURE"))
        .map(|v| truthy(&v))
        .unwrap_or(false)
}
