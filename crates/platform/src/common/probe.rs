//! Shared outcome type for best-effort network discovery probes.
//!
//! For a pentest report, "the probe could not run" (sandbox blocked bind/send,
//! or the recv timeout could not be set so a blocking socket would hang) must be
//! distinguishable from "the probe ran and found nothing on the network".

use serde::Serialize;

/// Why a discovery probe produced no results, or that it ran normally.
///
/// Serializes as a tagged JSON object (`{"status": "ran"}` or
/// `{"status": "skipped", "reason": "..."}`) so tool payloads can carry the
/// distinction through to the model and the report gate (#309).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ProbeOutcome {
    /// The probe ran to completion (results may still be empty).
    Ran,
    /// The probe could not run; the string is a short, non-PII reason.
    Skipped { reason: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ran_serializes_as_tagged_status() {
        let v = serde_json::to_value(ProbeOutcome::Ran).expect("serialize");
        assert_eq!(v, serde_json::json!({"status": "ran"}));
    }

    #[test]
    fn skipped_serializes_with_reason() {
        let v = serde_json::to_value(ProbeOutcome::Skipped {
            reason: "bind failed: permission denied".into(),
        })
        .expect("serialize");
        assert_eq!(
            v,
            serde_json::json!({
                "status": "skipped",
                "reason": "bind failed: permission denied",
            })
        );
    }
}
