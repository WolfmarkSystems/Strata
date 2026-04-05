pub mod email;
pub mod encrypted;
pub mod gmail;
pub mod outlook_deep;
pub mod outlook_full;
pub mod thunderbird;

pub use email::EmailParser;
pub use gmail::GmailParser;
pub use outlook_deep::OutlookDeepParser;
pub use outlook_full::OutlookFullParser;
pub use thunderbird::ThunderbirdParser;
