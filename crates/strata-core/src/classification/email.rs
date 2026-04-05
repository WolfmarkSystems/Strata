use super::scalpel::{
    read_prefix, read_text_prefix, DEFAULT_BINARY_MAX_BYTES, DEFAULT_TEXT_MAX_BYTES,
};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct EmailMessage {
    pub subject: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub date: Option<String>,
    pub body: Option<String>,
    pub attachments: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum MailStoreType {
    PST,
    DBX,
    OST,
    MBOX,
    Unknown,
}

pub fn parse_outlook_pst(path: &Path) -> Result<Vec<EmailMessage>, std::io::Error> {
    let mut messages = Vec::new();

    if !path.exists() {
        return Ok(messages);
    }

    let data = read_prefix(path, DEFAULT_BINARY_MAX_BYTES)?;

    if data.len() < 512 {
        return Ok(messages);
    }

    if &data[0..4] == b"!BDN" || &data[0..4] == b"BDN\x00" {
        messages.push(EmailMessage {
            subject: Some("[PST file detected]".to_string()),
            from: None,
            to: None,
            date: None,
            body: None,
            attachments: Vec::new(),
        });
    }

    Ok(messages)
}

pub fn parse_outlook_express_dbx(path: &Path) -> Result<Vec<EmailMessage>, std::io::Error> {
    let mut messages = Vec::new();

    if !path.exists() {
        return Ok(messages);
    }

    let data = read_prefix(path, DEFAULT_BINARY_MAX_BYTES)?;

    if data.len() < 512 {
        return Ok(messages);
    }

    if &data[0..4] == b"DXDB" || &data[4..8] == b"DXSB" {
        messages.push(EmailMessage {
            subject: Some("[DBX file detected]".to_string()),
            from: None,
            to: None,
            date: None,
            body: None,
            attachments: Vec::new(),
        });
    }

    Ok(messages)
}

pub fn parse_mbox(path: &Path) -> Result<Vec<EmailMessage>, std::io::Error> {
    let mut messages = Vec::new();

    if !path.exists() {
        return Ok(messages);
    }

    let content = read_text_prefix(path, DEFAULT_TEXT_MAX_BYTES * 8)?;

    let mut current_msg = None;

    for line in content.lines() {
        if let Some(from) = line.strip_prefix("From ") {
            if let Some(msg) = current_msg.take() {
                messages.push(msg);
            }
            current_msg = Some(EmailMessage {
                subject: None,
                from: Some(from.to_string()),
                to: None,
                date: None,
                body: None,
                attachments: Vec::new(),
            });
        } else if let Some(subject) = line.strip_prefix("Subject: ") {
            if let Some(ref mut msg) = current_msg {
                msg.subject = Some(subject.to_string());
            }
        } else if let Some(date) = line.strip_prefix("Date: ") {
            if let Some(ref mut msg) = current_msg {
                msg.date = Some(date.to_string());
            }
        }
    }

    if let Some(msg) = current_msg {
        messages.push(msg);
    }

    Ok(messages)
}

pub fn detect_mailbox_type(path: &Path) -> MailStoreType {
    if !path.exists() {
        return MailStoreType::Unknown;
    }

    if let Ok(data) = read_prefix(path, DEFAULT_BINARY_MAX_BYTES) {
        if data.len() >= 4 {
            if &data[0..4] == b"!BDN" || &data[0..4] == b"BDN\x00" {
                return MailStoreType::PST;
            }
            if &data[0..4] == b"DXDB" || &data[4..8] == b"DXSB" {
                return MailStoreType::DBX;
            }
        }

        if let Ok(content) = read_text_prefix(path, DEFAULT_TEXT_MAX_BYTES) {
            if content.starts_with("From ") {
                return MailStoreType::MBOX;
            }
        }
    }

    MailStoreType::Unknown
}
