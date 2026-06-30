//! Active Directory attack tools.
//!
//! A suite of one-shot AD attack wrappers driven by Pick's runner: each tool
//! spawns a process, runs it to completion, and captures stdout. Everything is
//! passed as an argv vector (never a shell string), and every operator-supplied
//! value is validated against a conservative allowlist before it reaches the
//! process boundary — mirroring `zap` and `metasploit`.
//!
//!   * [`CertipyTool`]  — AD CS / ESC certificate attacks (Certipy).
//!   * [`NetExecTool`]  — network service exploitation across SMB/WinRM/LDAP/...
//!     (`nxc`).
//!   * [`KerbruteTool`] — Kerberos pre-auth username enumeration / spraying.
//!   * [`BloodHoundTool`] — AD data collection (`bloodhound-python` ingestor).

mod common;

pub mod bloodhound;
pub mod certipy;
pub mod kerbrute;
pub mod netexec;

pub use bloodhound::BloodHoundTool;
pub use certipy::CertipyTool;
pub use kerbrute::KerbruteTool;
pub use netexec::NetExecTool;
