pub mod discord;
pub mod slack;
pub mod telegram;

pub use discord::DiscordParser;
pub use slack::SlackParser;
pub use telegram::TelegramParser;
