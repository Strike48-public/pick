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
pub mod dirb;
pub mod enum4linux;
pub mod hydra;
pub mod john;
pub mod masscan;
pub mod nikto;
pub mod rustscan;

// Phase 3 tools - Web Application Security
pub mod web;

// Phase 4 tools - Post-Exploitation & Lateral Movement
pub mod postexploit;

// Phase 5+ tools - Network, Forensics, Wireless, Specialized
pub mod forensics;
pub mod network;
pub mod specialized;
pub mod wireless;

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
pub use web::{
    AmassTool, ArjunTool, AssetfinderTool, CommixTool, DirsearchTool, FeroxbusterTool, FfufDnsTool,
    GauTool, GospiderTool, HakrawlerTool, HttpprobeTool, KatanaTool, NucleiTool, ParamspiderTool,
    SqlmapTool, SubfinderTool, Sublist3rTool, WaybackurlsTool, WfuzzTool, WpscanTool, XsstrikeTool,
};

// Phase 4 - Post-Exploitation
pub use postexploit::{
    CrackmapexecTool, EvilwinrmTool, ImpacketGetuserspnsTool, ImpacketPsexecTool,
    ImpacketSecretsdumpTool, ImpacketWmiexecTool, LinpeasTool,
};

// Phase 5+ - Network, Forensics, Wireless, Specialized
pub use forensics::ExiftoolTool;
pub use network::{
    ArpScanTool, BettercapTool, MasscanFastTool, NbtscanTool, NetdiscoverTool, NmapVulnTool,
    ResponderTool, TsharkTool,
};
pub use specialized::{
    CewlTool, CrunchTool, DnsenumTool, DnsreconTool, Enum4linuxNgTool, FierceTool, HashcatTool,
    NcatTool, SearchsploitTool, SmbmapTool, SocatTool, SslscanTool, TestsslTool, TheHarvesterTool,
    WhoisTool,
};
pub use wireless::AircrackngTool;
