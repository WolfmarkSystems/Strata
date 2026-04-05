pub mod hibernation;
pub mod key_scraper;
pub mod pagefile;
pub mod parser;
pub mod raw_dump;

pub use hibernation::HibernationParser;
pub use key_scraper::{AesKey, KeyScraper};
pub use pagefile::{MemoryPage, PagefileParser};
pub use parser::MemoryParser;
pub use raw_dump::{EProcess, RawDumpParser};
