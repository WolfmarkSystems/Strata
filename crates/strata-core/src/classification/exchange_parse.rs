use super::scalpel::{read_text_prefix, DEFAULT_TEXT_MAX_BYTES};
use std::env;
use std::path::{Path, PathBuf};

pub fn get_exchange_mailboxes() -> Vec<ExchangeMailbox> {
    let path = env::var("FORENSIC_EXCHANGE_MAILBOXES")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from("artifacts")
                .join("exchange")
                .join("mailboxes.csv")
        });
    parse_exchange_mailboxes(&path)
}

#[derive(Debug, Clone, Default)]
pub struct ExchangeMailbox {
    pub name: String,
    pub email: String,
    pub size: u64,
    pub item_count: u32,
    pub last_logon: u64,
}

pub fn get_exchange_messages() -> Vec<ExchangeMessage> {
    let path = env::var("FORENSIC_EXCHANGE_MESSAGES")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from("artifacts")
                .join("exchange")
                .join("messages.csv")
        });
    parse_exchange_messages(&path)
}

#[derive(Debug, Clone, Default)]
pub struct ExchangeMessage {
    pub mailbox: String,
    pub subject: String,
    pub sender: String,
    pub recipients: Vec<String>,
    pub timestamp: u64,
    pub has_attachments: bool,
}

pub fn get_exchange_attachments() -> Vec<ExchangeAttachment> {
    let path = env::var("FORENSIC_EXCHANGE_ATTACHMENTS")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from("artifacts")
                .join("exchange")
                .join("attachments.csv")
        });
    parse_exchange_attachments(&path)
}

#[derive(Debug, Clone, Default)]
pub struct ExchangeAttachment {
    pub message_id: String,
    pub file_name: String,
    pub size: u64,
}

pub fn get_exchange_transport_logs() -> Vec<TransportLog> {
    let path = env::var("FORENSIC_EXCHANGE_TRANSPORT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from("artifacts")
                .join("exchange")
                .join("transport.csv")
        });
    parse_transport_logs(&path)
}

#[derive(Debug, Clone, Default)]
pub struct TransportLog {
    pub timestamp: u64,
    pub source: String,
    pub destination: String,
    pub subject: String,
    pub status: String,
}

fn parse_exchange_mailboxes(path: &Path) -> Vec<ExchangeMailbox> {
    let content = match read_text_prefix(path, DEFAULT_TEXT_MAX_BYTES * 4) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for row in parse_simple_csv(&content).into_iter().skip(1) {
        if row.len() < 5 {
            continue;
        }
        out.push(ExchangeMailbox {
            name: row[0].clone(),
            email: row[1].clone(),
            size: row[2].parse::<u64>().unwrap_or(0),
            item_count: row[3].parse::<u32>().unwrap_or(0),
            last_logon: row[4].parse::<u64>().unwrap_or(0),
        });
    }
    out
}

fn parse_exchange_messages(path: &Path) -> Vec<ExchangeMessage> {
    let content = match read_text_prefix(path, DEFAULT_TEXT_MAX_BYTES * 4) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for row in parse_simple_csv(&content).into_iter().skip(1) {
        if row.len() < 6 {
            continue;
        }
        out.push(ExchangeMessage {
            mailbox: row[0].clone(),
            subject: row[1].clone(),
            sender: row[2].clone(),
            recipients: row[3]
                .split(';')
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .collect(),
            timestamp: row[4].parse::<u64>().unwrap_or(0),
            has_attachments: row[5].eq_ignore_ascii_case("true") || row[5] == "1",
        });
    }
    out
}

fn parse_exchange_attachments(path: &Path) -> Vec<ExchangeAttachment> {
    let content = match read_text_prefix(path, DEFAULT_TEXT_MAX_BYTES * 4) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for row in parse_simple_csv(&content).into_iter().skip(1) {
        if row.len() < 3 {
            continue;
        }
        out.push(ExchangeAttachment {
            message_id: row[0].clone(),
            file_name: row[1].clone(),
            size: row[2].parse::<u64>().unwrap_or(0),
        });
    }
    out
}

fn parse_transport_logs(path: &Path) -> Vec<TransportLog> {
    let content = match read_text_prefix(path, DEFAULT_TEXT_MAX_BYTES * 4) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for row in parse_simple_csv(&content).into_iter().skip(1) {
        if row.len() < 5 {
            continue;
        }
        out.push(TransportLog {
            timestamp: row[0].parse::<u64>().unwrap_or(0),
            source: row[1].clone(),
            destination: row[2].clone(),
            subject: row[3].clone(),
            status: row[4].clone(),
        });
    }
    out
}

fn parse_simple_csv(content: &str) -> Vec<Vec<String>> {
    content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            line.split(',')
                .map(|v| v.trim().trim_matches('"').to_string())
                .collect::<Vec<String>>()
        })
        .collect()
}
