//! Compile-time environment defaults selected via Cargo features.
//!
//! - `dev-defaults`: local k8s cluster (*.strike48.test), TLS insecure
//! - `prod-defaults`: production (*.strike48.com), TLS strict
//! - Neither feature: falls back to prod defaults (safe default)

#[cfg(all(feature = "dev-defaults", feature = "prod-defaults"))]
compile_error!("Features `dev-defaults` and `prod-defaults` are mutually exclusive");

#[cfg(feature = "dev-defaults")]
mod values {
    pub const DEFAULT_CONNECTOR_HOST: &str = "wss://studio.strike48.com";
    pub const DEFAULT_TLS_INSECURE: bool = true;
    pub const DEFAULT_ENV_LABEL: &str = "Development";
    pub const DEFAULT_TENANT_ID: &str = "default";
}

#[cfg(not(feature = "dev-defaults"))]
mod values {
    // Prod defaults: used for prod-defaults feature OR when no feature is specified (safe fallback)
    pub const DEFAULT_CONNECTOR_HOST: &str = "wss://studio.strike48.com";
    pub const DEFAULT_TLS_INSECURE: bool = true; // TODO: set to false once prod has a valid TLS cert
    pub const DEFAULT_ENV_LABEL: &str = "Production";
    pub const DEFAULT_TENANT_ID: &str = "default";
}

pub use values::*;
