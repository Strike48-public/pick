//! Session budget envelope for the agent tool loop (agent hardening C3).
//!
//! The Red Team agent's chat loop runs on the Strike48 platform; Pick is the
//! connector that executes its tool calls. Honeyslop's RESOURCE-WASTE lesson
//! applies to *our own* agents: an unbounded loop with auto-approved tools
//! can burn the whole engagement's iteration budget on decoy targets or a
//! stuck agent, leaving no cheap termination condition. This module gives the
//! connector a per-engagement envelope — a rolling cap on tool executions plus
//! a stall detector — so spend stays bounded and observable.
//!
//! ## Enforcement model
//!
//! * **Hard cap**: once `max_executions` is reached, further tool calls are
//!   refused with a clear "budget exhausted" error the agent can see, so it
//!   winds down instead of retrying blindly.
//! * **Stall detector**: K consecutive tool calls that produce no state change
//!   (no evidence produced, no success) signal a loop; the connector emits a
//!   warning the orchestrator can escalate (advisory first, strict later).
//! * **Per-aggression defaults**: Conservative/Balanced/Aggressive/Maximum get
//!   progressively larger envelopes, mirroring `AggressionLevel`'s cost model.

use crate::aggression::AggressionLevel;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Default maximum tool executions per engagement, by aggression level.
///
/// These are deliberately generous compared to a real engagement's useful
/// tool-call count (a typical scan issues dozens of calls, not thousands) so
/// the cap only trips on runaway/degenerate loops, not legitimate deep scans.
/// They scale with the level's documented cost multiplier.
pub fn default_budget(level: AggressionLevel) -> BudgetConfig {
    match level {
        AggressionLevel::Conservative => BudgetConfig {
            max_executions: 200,
            stall_threshold: 8,
        },
        AggressionLevel::Balanced => BudgetConfig {
            max_executions: 500,
            stall_threshold: 8,
        },
        AggressionLevel::Aggressive => BudgetConfig {
            max_executions: 1_000,
            stall_threshold: 8,
        },
        AggressionLevel::Maximum => BudgetConfig {
            max_executions: 2_000,
            stall_threshold: 8,
        },
    }
}

/// Tuneable envelope parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetConfig {
    /// Hard cap on tool executions per engagement. Exceeding it refuses the
    /// call with [`BudgetError::Exhausted`].
    pub max_executions: u32,
    /// Consecutive executions producing no success and no new evidence trigger
    /// the stall detector (advisory warning first).
    pub stall_threshold: u32,
}

impl Default for BudgetConfig {
    fn default() -> Self {
        BudgetConfig {
            max_executions: 500,
            stall_threshold: 8,
        }
    }
}

/// Outcome of a budget check before executing a tool call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetCheck {
    /// Proceed with execution.
    Ok,
    /// The envelope is exhausted; the call must be refused.
    Exhausted,
    /// Stall detector tripped — warn, but still allow the call (advisory).
    StallWarning,
}

/// Why a request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BudgetError {
    #[error("session budget exhausted: {used}/{max} tool executions used. The agent should wind down and produce its report.")]
    Exhausted { used: u32, max: u32 },
}

/// Mutable, shareable per-engagement budget.
#[derive(Debug, Clone)]
pub struct SessionBudget {
    inner: Arc<RwLock<BudgetState>>,
}

#[derive(Debug)]
struct BudgetState {
    config: BudgetConfig,
    executions_used: u32,
    consecutive_stalls: u32,
    stall_warned: bool,
}

impl Default for SessionBudget {
    fn default() -> Self {
        Self::new(BudgetConfig::default())
    }
}

impl SessionBudget {
    /// Create a fresh budget with the given config. Each engagement (or
    /// connector instance) owns one; `begin_scan` resets it.
    pub fn new(config: BudgetConfig) -> Self {
        Self {
            inner: Arc::new(RwLock::new(BudgetState {
                config,
                executions_used: 0,
                consecutive_stalls: 0,
                stall_warned: false,
            })),
        }
    }

    /// Default budget for the given aggression level.
    pub fn default_for(level: AggressionLevel) -> Self {
        Self::new(default_budget(level))
    }

    /// Check whether a tool call may proceed, returning the disposition.
    /// Does not mutate; call [`SessionBudget::record`] after a real execution.
    pub async fn check(&self) -> BudgetCheck {
        let state = self.inner.read().await;
        if state.executions_used >= state.config.max_executions {
            return BudgetCheck::Exhausted;
        }
        if !state.stall_warned && state.consecutive_stalls >= state.config.stall_threshold {
            return BudgetCheck::StallWarning;
        }
        BudgetCheck::Ok
    }

    /// Record a completed tool execution. `made_progress` should be true when
    /// the call produced new evidence or otherwise advanced the engagement;
    /// false feeds the stall detector.
    pub async fn record(&self, made_progress: bool) {
        let mut state = self.inner.write().await;
        state.executions_used = state.executions_used.saturating_add(1);
        if made_progress {
            state.consecutive_stalls = 0;
        } else {
            state.consecutive_stalls = state.consecutive_stalls.saturating_add(1);
            if state.stall_warned {
                state.stall_warned = false; // allow another advisory after recovery
            }
        }
    }

    /// Mark the stall warning as emitted (so it fires once per threshold hit,
    /// not on every subsequent call).
    pub async fn mark_stall_warned(&self) {
        self.inner.write().await.stall_warned = true;
    }

    /// Reset the envelope (called on `begin_scan` for a fresh engagement).
    pub async fn reset(&self) {
        let mut state = self.inner.write().await;
        state.executions_used = 0;
        state.consecutive_stalls = 0;
        state.stall_warned = false;
    }

    /// Current usage snapshot (for observability / tests).
    pub async fn usage(&self) -> (u32, u32) {
        let state = self.inner.read().await;
        (state.executions_used, state.config.max_executions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_scale_with_aggression() {
        let cons = default_budget(AggressionLevel::Conservative);
        let bal = default_budget(AggressionLevel::Balanced);
        let aggr = default_budget(AggressionLevel::Aggressive);
        let max = default_budget(AggressionLevel::Maximum);
        assert!(cons.max_executions < bal.max_executions);
        assert!(bal.max_executions < aggr.max_executions);
        assert!(aggr.max_executions < max.max_executions);
    }

    #[tokio::test]
    async fn budget_refuses_when_exhausted() {
        let budget = SessionBudget::new(BudgetConfig {
            max_executions: 2,
            stall_threshold: 8,
        });
        assert_eq!(budget.check().await, BudgetCheck::Ok);
        budget.record(true).await;
        assert_eq!(budget.check().await, BudgetCheck::Ok);
        budget.record(true).await;
        assert_eq!(budget.check().await, BudgetCheck::Exhausted);
        let (used, max) = budget.usage().await;
        assert_eq!((used, max), (2, 2));
    }

    #[tokio::test]
    async fn stall_detector_warns_once_then_recovers() {
        let budget = SessionBudget::new(BudgetConfig {
            max_executions: 100,
            stall_threshold: 3,
        });
        // Three consecutive no-progress calls trip the advisory.
        budget.record(false).await;
        budget.record(false).await;
        assert_eq!(budget.check().await, BudgetCheck::Ok);
        budget.record(false).await;
        assert_eq!(budget.check().await, BudgetCheck::StallWarning);
        budget.mark_stall_warned().await;
        // Subsequent calls without recovery are Ok (advisory fired once),
        assert_eq!(budget.check().await, BudgetCheck::Ok);
        // ... until progress resets the counter.
        budget.record(true).await;
        budget.record(false).await;
        assert_eq!(budget.check().await, BudgetCheck::Ok);
    }

    #[tokio::test]
    async fn reset_starts_a_fresh_envelope() {
        let budget = SessionBudget::new(BudgetConfig {
            max_executions: 1,
            stall_threshold: 3,
        });
        budget.record(false).await;
        assert_eq!(budget.check().await, BudgetCheck::Exhausted);
        budget.reset().await;
        assert_eq!(budget.check().await, BudgetCheck::Ok);
    }
}
