//! OTT approval flow, credentials handling, and token refresh logic.
//!
//! Previously contained custom OTT exchange and post-registration auth.
//! Now handled by the SDK's `ConnectorRunner` internally (connection
//! management, OTT exchange, session tokens, JWT refresh).
