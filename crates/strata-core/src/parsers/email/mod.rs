pub mod apple_mail;
#[allow(clippy::module_inception)]
pub mod email;
pub mod encrypted;
pub mod gmail;
pub mod outlook_deep;
pub mod outlook_full;
pub mod thunderbird;

pub use apple_mail::AppleMailParser;
pub use email::EmailParser;
pub use gmail::GmailParser;
pub use outlook_deep::OutlookDeepParser;
pub use outlook_full::OutlookFullParser;
pub use thunderbird::ThunderbirdParser;
