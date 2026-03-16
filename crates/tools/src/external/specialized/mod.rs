//! Specialized tools (password cracking, exploit search, etc.)

pub mod hashcat;
pub mod searchsploit;

pub use hashcat::HashcatTool;
pub use searchsploit::SearchsploitTool;
