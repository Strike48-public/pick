//! Specialized tools (password cracking, exploit search, etc.)

pub mod hashcat;
pub mod searchsploit;
pub mod cewl;
pub mod ncat;

pub use hashcat::HashcatTool;
pub use searchsploit::SearchsploitTool;
pub use cewl::CewlTool;
pub use ncat::NcatTool;
