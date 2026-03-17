//! Specialized tools (password cracking, exploit search, etc.)

pub mod hashcat;
pub mod searchsploit;
pub mod cewl;
pub mod ncat;
pub mod socat;
pub mod crunch;

pub use hashcat::HashcatTool;
pub use searchsploit::SearchsploitTool;
pub use cewl::CewlTool;
pub use ncat::NcatTool;
pub use socat::SocatTool;
pub use crunch::CrunchTool;
