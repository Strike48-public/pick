//! CyberChef integration for Pick
//!
//! This crate provides comprehensive CyberChef integration including:
//! - Embedded CyberChef UI via iframe
//! - Programmatic recipe execution via tool
//! - Pre-built recipe library for common pentest operations
//! - Recipe management and persistence

pub mod recipes;
pub mod tool;

// Re-exports for convenience
pub use recipes::{RecipeLibrary, RecipeInfo};
pub use tool::CyberChefTool;
