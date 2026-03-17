//! Specialized tools (password cracking, exploit search, etc.)

pub mod hashcat;
pub mod searchsploit;
pub mod cewl;
pub mod ncat;
pub mod socat;
pub mod crunch;
pub mod theharvester;
pub mod dnsrecon;
pub mod dnsenum;
pub mod fierce;

pub use hashcat::HashcatTool;
pub use searchsploit::SearchsploitTool;
pub use cewl::CewlTool;
pub use ncat::NcatTool;
pub use socat::SocatTool;
pub use crunch::CrunchTool;
pub use theharvester::TheHarvesterTool;
pub use dnsrecon::DnsreconTool;
pub use dnsenum::DnsenumTool;
pub use fierce::FierceTool;
