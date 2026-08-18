//! Shared outcome type for best-effort network discovery probes.
//!
//! For a pentest report, "the probe could not run" (sandbox blocked bind/send,
//! or the recv timeout could not be set so a blocking socket would hang) must be
//! distinguishable from "the probe ran and found nothing on the network".

/// Why a discovery probe produced no results, or that it ran normally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// The probe ran to completion (results may still be empty).
    Ran,
    /// The probe could not run; the string is a short, non-PII reason.
    Skipped(String),
}
