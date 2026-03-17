//! Automated toolchain execution system
//!
//! This module provides infrastructure for executing multi-tool attack chains
//! with intelligent pivoting, progress tracking, and failure recovery.

pub mod engine;
pub mod playbook;
pub mod session;
pub mod webapp;

pub use engine::ToolchainEngine;
pub use playbook::{Playbook, PlaybookManager, Step, StepCondition};
pub use session::{
    AttackProfile, ExecutionMode, ExecutionStatus, Finding, PentestSession, ToolExecution,
};
pub use webapp::WebAppToolchain;
