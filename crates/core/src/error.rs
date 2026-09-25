//! Error types for the pentest connector.
//!
//! Most variants carry a message `String`, and a failure's cause used to be
//! folded into that string with `format!("...: {e}")`, which kept the cause's
//! text but dropped everything below it (a reqwest error's TLS or DNS detail,
//! an SDK error's inner cause). [`Error::with_source`] attaches the cause as a
//! real `source()` without changing the message, and [`Error::chain`] renders
//! the whole chain at the boundaries where an error leaves the process: the
//! `ToolResult` sent to Strike48, the UI event, and the failure log line
//! (pick#476).

use thiserror::Error;

/// Main error type for the pentest connector
#[derive(Error, Debug)]
pub enum Error {
    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Tool execution error: {0}")]
    ToolExecution(String),

    #[error("Tool not found: {0}")]
    ToolNotFound(String),

    #[error("Invalid parameters: {0}")]
    InvalidParams(String),

    #[error("Platform not supported: {0}")]
    PlatformNotSupported(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Capture error: {0}")]
    Capture(String),

    #[error("SDK error: {0}")]
    Sdk(String),

    #[error("File browser error: {0}")]
    FileBrowser(String),

    #[error("matrix: {0}")]
    Matrix(String),

    #[error("Unknown error: {0}")]
    Unknown(String),

    /// An error with its underlying cause attached; see [`Error::with_source`].
    ///
    /// `Display` is the inner error's, so existing messages are unchanged.
    /// The cause is reachable through `std::error::Error::source` and is
    /// rendered by [`Error::chain`]. Match on [`Error::kind`] rather than on
    /// this variant.
    #[error("{error}")]
    Caused {
        error: Box<Error>,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },
}

/// Result type alias using our Error type
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// Attach the cause of this error.
    ///
    /// The message stays as it is (keep formatting the cause into it where
    /// callers display the error on its own); the cause becomes `source()`
    /// so its own chain is preserved for [`Error::chain`].
    pub fn with_source<E>(self, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        self.with_boxed_source(Box::new(source))
    }

    /// [`Error::with_source`] for a cause that is already boxed, such as an
    /// `anyhow::Error` converted with `.into()`.
    pub fn with_boxed_source(
        self,
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    ) -> Self {
        Error::Caused {
            error: Box::new(self),
            source,
        }
    }

    /// The classified error underneath any attached causes.
    ///
    /// Use this when matching on a variant, so a call site that attaches a
    /// cause does not change what the error is.
    pub fn kind(&self) -> &Error {
        let mut current = self;
        while let Error::Caused { error, .. } = current {
            current = error;
        }
        current
    }

    /// The full cause chain, outermost first, joined with `: `.
    ///
    /// A segment that only restates the end of the text so far is skipped,
    /// so a variant whose message already embeds its source's text (the
    /// `#[from]` variants, or a `format!("...: {e}")` message) does not
    /// print that text twice.
    ///
    /// The walk is structural rather than a plain `source()` loop: each
    /// [`Error::with_source`] wraps the previous error in a `Caused`, and
    /// thiserror's derived `source()` only exposes that wrapper's own
    /// attachment, not the one nested inside it. Stacking `with_source` twice
    /// would therefore drop the middle cause from a naive loop. Here the
    /// classified [`Error::kind`] is rendered first, then every attached cause
    /// in innermost-first order, each with its own `source()` chain.
    pub fn chain(&self) -> String {
        let mut rendered = String::new();
        push_source_chain(&mut rendered, self.kind());
        for source in self.attached_sources() {
            push_source_chain(&mut rendered, source);
        }
        rendered
    }

    /// The attached causes, innermost attachment first.
    ///
    /// Each [`Error::with_source`] pushes a `Caused` wrapper around the current
    /// error; this unwinds that stack so a doubly-attached cause is not lost.
    fn attached_sources(&self) -> Vec<&(dyn std::error::Error + 'static)> {
        let mut sources: Vec<&(dyn std::error::Error + 'static)> = Vec::new();
        let mut current = self;
        while let Error::Caused { error, source } = current {
            sources.push(source.as_ref());
            current = error;
        }
        sources.reverse();
        sources
    }
}

/// Render an error and its `source()` chain, outermost first, joined with
/// `: `, skipping a segment that merely restates the text so far.
///
/// Public so a tool site holding a foreign error (not an [`Error`]) can render
/// the same underlying cause detail — TLS, DNS, connection refused — that the
/// boundary [`Error::chain`] produces, instead of a bare top-line
/// `to_string()`.
pub fn source_chain(err: &dyn std::error::Error) -> String {
    let mut rendered = String::new();
    push_source_chain(&mut rendered, err);
    rendered
}

/// Append `err` and its `source()` chain to `rendered`, applying the same
/// restatement-dedupe [`Error::chain`] uses.
fn push_source_chain(rendered: &mut String, err: &dyn std::error::Error) {
    let mut current: Option<&dyn std::error::Error> = Some(err);
    while let Some(err) = current {
        let segment = err.to_string();
        if rendered.is_empty() {
            rendered.push_str(&segment);
        } else if !rendered.ends_with(&segment) {
            rendered.push_str(": ");
            rendered.push_str(&segment);
        }
        current = err.source();
    }
}

impl From<anyhow::Error> for Error {
    /// Keeps the outermost context as the message and the rest of the
    /// `anyhow` chain as the source, so `.context(...)` layers survive.
    fn from(err: anyhow::Error) -> Self {
        Error::Unknown(err.to_string()).with_boxed_source(err.into())
    }
}

impl From<strike48_connector::ConnectorError> for Error {
    fn from(err: strike48_connector::ConnectorError) -> Self {
        Error::Sdk(err.to_string()).with_source(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context as _;
    use std::error::Error as _;

    fn io_error(message: &str) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::NotFound, message.to_string())
    }

    #[test]
    fn with_source_keeps_display_and_exposes_the_cause() {
        let err = Error::ToolExecution("nmap failed".into())
            .with_source(io_error("nmap: command not found"));

        assert_eq!(err.to_string(), "Tool execution error: nmap failed");
        assert_eq!(
            err.source().map(|s| s.to_string()),
            Some("nmap: command not found".to_string())
        );
        assert_eq!(
            err.chain(),
            "Tool execution error: nmap failed: nmap: command not found"
        );
    }

    #[test]
    fn chain_does_not_repeat_a_cause_already_in_the_message() {
        let from_io = Error::from(io_error("disk full"));
        assert_eq!(from_io.chain(), "IO error: disk full");

        let cause = io_error("connection refused");
        let formatted = Error::Network(format!("studio unreachable: {cause}")).with_source(cause);
        assert_eq!(
            formatted.chain(),
            "Network error: studio unreachable: connection refused"
        );
    }

    #[test]
    fn anyhow_context_layers_survive_the_conversion() {
        let inner: anyhow::Result<()> = Err(anyhow::anyhow!("dial tcp 10.0.0.5:443: timed out"));
        let err = Error::from(inner.context("connect to studio").unwrap_err());

        assert_eq!(err.to_string(), "Unknown error: connect to studio");
        assert_eq!(
            err.chain(),
            "Unknown error: connect to studio: dial tcp 10.0.0.5:443: timed out"
        );
    }

    #[test]
    fn sdk_error_keeps_its_source() {
        let sdk = strike48_connector::ConnectorError::Timeout("register".into());
        let display = sdk.to_string();
        let err = Error::from(sdk);

        assert!(matches!(err.kind(), Error::Sdk(_)));
        assert_eq!(err.to_string(), format!("SDK error: {display}"));
        assert!(
            err.source().is_some(),
            "SDK error must be reachable as source"
        );
    }

    #[test]
    fn kind_sees_through_attached_causes() {
        let err = Error::Timeout("nmap".into())
            .with_source(io_error("first"))
            .with_source(io_error("second"));

        assert!(matches!(err.kind(), Error::Timeout(_)));
        assert!(!matches!(err, Error::Timeout(_)));
    }

    #[test]
    fn chain_keeps_every_cause_when_sources_are_stacked() {
        // Two `with_source` calls nest `Caused` twice. thiserror's derived
        // `source()` only exposes the outer attachment, so a naive source loop
        // renders "Timeout: nmap: second" and silently drops "first". The
        // structural walk keeps every cause, innermost attachment first.
        let err = Error::Timeout("nmap".into())
            .with_source(io_error("first"))
            .with_source(io_error("second"));

        assert_eq!(err.chain(), "Timeout: nmap: first: second");
    }

    #[test]
    fn source_chain_renders_a_foreign_error_and_its_causes() {
        // A tool site holding a foreign error (not an `Error`) gets the same
        // cause detail the boundary `chain()` produces.
        #[derive(Debug)]
        struct Outer(std::io::Error);
        impl std::fmt::Display for Outer {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "connect failed")
            }
        }
        impl std::error::Error for Outer {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.0)
            }
        }

        let err = Outer(io_error("connection refused"));
        assert_eq!(source_chain(&err), "connect failed: connection refused");
    }
}
