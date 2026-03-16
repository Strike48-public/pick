//! External tool integrations (BlackArch tools)
//!
//! This module provides integrations with external penetration testing tools
//! from the BlackArch repository. Tools are installed on-demand via pacman
//! and executed through the existing sandbox infrastructure.

pub mod install;
pub mod parsers;
pub mod runner;

// Tier 1 tools (subprocess-based, single binaries)
// Phase 1 tools
pub mod ffuf;
pub mod gobuster;
pub mod nmap;

// Phase 2 tools
pub mod rustscan;
pub mod masscan;
pub mod nikto;
pub mod dirb;
pub mod enum4linux;
pub mod hydra;
pub mod john;

// Phase 3 tools - Web Application Security
pub mod web;

// Re-exports
// Phase 1
pub use ffuf::FfufTool;
pub use gobuster::GobusterTool;
pub use nmap::NmapTool;

// Phase 2
pub use dirb::DirbTool;
pub use enum4linux::Enum4linuxTool;
pub use hydra::HydraTool;
pub use john::JohnTool;
pub use masscan::MasscanTool;
pub use nikto::NiktoTool;
pub use rustscan::RustScanTool;

// Phase 3 - Web
pub use web::{FeroxbusterTool, NucleiTool, SqlmapTool, WfuzzTool, WpscanTool};
