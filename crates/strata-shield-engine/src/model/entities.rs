use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Identity {
    pub id: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Device {
    pub id: String,
    pub platform: String,
    pub hostname: Option<String>,
    pub serial_number: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Account {
    pub id: String,
    pub provider: String,
    pub username: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Message {
    pub id: String,
    pub account_id: Option<String>,
    pub sender: Option<String>,
    pub recipient: Option<String>,
    pub body: Option<String>,
    pub timestamp_utc: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Call {
    pub id: String,
    pub account_id: Option<String>,
    pub direction: Option<String>,
    pub timestamp_utc: Option<String>,
    pub duration_seconds: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Location {
    pub id: String,
    pub latitude: f64,
    pub longitude: f64,
    pub timestamp_utc: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Media {
    pub id: String,
    pub path: String,
    pub sha256: Option<String>,
    pub created_utc: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebEvent {
    pub id: String,
    pub url: String,
    pub title: Option<String>,
    pub timestamp_utc: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SystemEvent {
    pub id: String,
    pub event_type: String,
    pub summary: String,
    pub timestamp_utc: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppEvent {
    pub id: String,
    pub app_name: String,
    pub event_type: String,
    pub summary: String,
    pub timestamp_utc: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "record")]
pub enum CanonicalRecord {
    Identity(Identity),
    Device(Device),
    Account(Account),
    Message(Message),
    Call(Call),
    LocationKey(String),
    Media(Media),
    WebEvent(WebEvent),
    SystemEvent(SystemEvent),
    AppEvent(AppEvent),
}
