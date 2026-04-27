use crate::parser::{ArtifactParser, ParsedArtifact, ParserError};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Apple Mail .emlx parser
/// Path: ~/Library/Mail/V*/Mailboxes/**/*.emlx
///
/// Format: 4-byte length prefix (decimal ASCII + newline), RFC 2822 email body,
/// Apple plist metadata trailer. Each .emlx is one email message.
pub struct AppleMailParser;

impl Default for AppleMailParser {
    fn default() -> Self {
        Self::new()
    }
}

impl AppleMailParser {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AppleMailEntry {
    pub message_id: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub cc: Option<String>,
    pub subject: Option<String>,
    pub date: Option<String>,
    pub date_epoch: Option<i64>,
    pub content_type: Option<String>,
    pub x_mailer: Option<String>,
    pub in_reply_to: Option<String>,
    pub references: Option<String>,
    pub body_preview: Option<String>,
    pub has_attachments: bool,
    pub plist_metadata: Option<serde_json::Value>,
    pub mailbox_path: Option<String>,
    pub flags: Option<u32>,
}

impl ArtifactParser for AppleMailParser {
    fn name(&self) -> &str {
        "Apple Mail Parser"
    }

    fn artifact_type(&self) -> &str {
        "email"
    }

    fn target_patterns(&self) -> Vec<&str> {
        vec!["*.emlx", "*.partial.emlx", "*.emlxpart"]
    }

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError> {
        let mut artifacts = Vec::new();

        if data.is_empty() {
            return Ok(artifacts);
        }

        let text = String::from_utf8_lossy(data);

        // emlx format: first line is byte count (decimal), then RFC 2822 email, then plist
        let (email_body, plist_data) = split_emlx(&text);

        let mut entry = AppleMailEntry {
            message_id: None,
            from: None,
            to: None,
            cc: None,
            subject: None,
            date: None,
            date_epoch: None,
            content_type: None,
            x_mailer: None,
            in_reply_to: None,
            references: None,
            body_preview: None,
            has_attachments: false,
            plist_metadata: None,
            mailbox_path: path.parent().map(|p| p.to_string_lossy().to_string()),
            flags: None,
        };

        // Parse RFC 2822 headers
        if let Some(body) = &email_body {
            let mut in_headers = true;
            let mut body_lines = Vec::new();
            let mut current_header: Option<(String, String)> = None;

            for line in body.lines() {
                if in_headers {
                    if line.is_empty() {
                        // End of headers
                        if let Some((key, val)) = current_header.take() {
                            set_header_field(&mut entry, &key, &val);
                        }
                        in_headers = false;
                        continue;
                    }

                    // Continuation line (starts with whitespace)
                    if line.starts_with(' ') || line.starts_with('\t') {
                        if let Some((_, ref mut val)) = current_header {
                            val.push(' ');
                            val.push_str(line.trim());
                        }
                        continue;
                    }

                    // New header
                    if let Some((key, val)) = current_header.take() {
                        set_header_field(&mut entry, &key, &val);
                    }

                    if let Some(colon_pos) = line.find(':') {
                        let key = line[..colon_pos].trim().to_lowercase();
                        let val = line[colon_pos + 1..].trim().to_string();
                        current_header = Some((key, val));
                    }
                } else {
                    body_lines.push(line);
                    if body_lines.len() >= 10 {
                        break;
                    }
                }
            }

            if let Some((key, val)) = current_header {
                set_header_field(&mut entry, &key, &val);
            }

            if !body_lines.is_empty() {
                let preview = body_lines.join("\n");
                let preview = if preview.len() > 500 {
                    format!("{}...", &preview[..500])
                } else {
                    preview
                };
                entry.body_preview = Some(preview);
            }
        }

        // Check for attachments
        if let Some(ref ct) = entry.content_type {
            entry.has_attachments =
                ct.contains("multipart/mixed") || ct.contains("multipart/related");
        }

        // Parse plist metadata if present
        if let Some(ref plist_str) = plist_data {
            entry.plist_metadata = parse_emlx_plist(plist_str);
            if let Some(ref meta) = entry.plist_metadata {
                if let Some(flags) = meta.get("flags").and_then(|v| v.as_u64()) {
                    entry.flags = Some(flags as u32);
                }
            }
        }

        // Attempt to parse date to epoch
        entry.date_epoch = entry.date.as_deref().and_then(parse_rfc2822_to_epoch);

        let from = entry.from.as_deref().unwrap_or("unknown");
        let subject = entry.subject.as_deref().unwrap_or("(no subject)");
        let desc = format!("Apple Mail: {} — {}", from, subject);

        artifacts.push(ParsedArtifact {
            timestamp: entry.date_epoch,
            artifact_type: "email".to_string(),
            description: desc,
            source_path: path.to_string_lossy().to_string(),
            json_data: serde_json::to_value(&entry).unwrap_or_default(),
        });

        Ok(artifacts)
    }
}

fn split_emlx(text: &str) -> (Option<String>, Option<String>) {
    // First line is the byte count of the email body
    let first_newline = match text.find('\n') {
        Some(pos) => pos,
        None => return (Some(text.to_string()), None),
    };

    let count_str = text[..first_newline].trim();
    let byte_count = count_str.parse::<usize>().unwrap_or(0);

    if byte_count == 0 {
        // Not a valid emlx length prefix; treat entire content as email
        return (Some(text.to_string()), None);
    }

    let body_start = first_newline + 1;
    let body_end = (body_start + byte_count).min(text.len());
    let email_body = text[body_start..body_end].to_string();

    let plist_data = if body_end < text.len() {
        let remainder = text[body_end..].trim();
        if !remainder.is_empty() {
            Some(remainder.to_string())
        } else {
            None
        }
    } else {
        None
    };

    (Some(email_body), plist_data)
}

fn set_header_field(entry: &mut AppleMailEntry, key: &str, val: &str) {
    match key {
        "message-id" => entry.message_id = Some(val.to_string()),
        "from" => entry.from = Some(val.to_string()),
        "to" => entry.to = Some(val.to_string()),
        "cc" => entry.cc = Some(val.to_string()),
        "subject" => entry.subject = Some(val.to_string()),
        "date" => entry.date = Some(val.to_string()),
        "content-type" => entry.content_type = Some(val.to_string()),
        "x-mailer" => entry.x_mailer = Some(val.to_string()),
        "in-reply-to" => entry.in_reply_to = Some(val.to_string()),
        "references" => entry.references = Some(val.to_string()),
        _ => {}
    }
}

fn parse_emlx_plist(plist_str: &str) -> Option<serde_json::Value> {
    // Simple XML plist extraction for common fields
    let mut result = serde_json::Map::new();

    // Extract integer values like <key>flags</key><integer>8590195713</integer>
    let mut remaining = plist_str;
    while let Some(key_start) = remaining.find("<key>") {
        let key_content_start = key_start + 5;
        if let Some(key_end) = remaining[key_content_start..].find("</key>") {
            let key = &remaining[key_content_start..key_content_start + key_end];
            let after_key = &remaining[key_content_start + key_end + 6..];

            if let Some(int_start) = after_key.find("<integer>") {
                let int_content_start = int_start + 9;
                if let Some(int_end) = after_key[int_content_start..].find("</integer>") {
                    let int_str = &after_key[int_content_start..int_content_start + int_end];
                    if let Ok(val) = int_str.trim().parse::<i64>() {
                        result.insert(
                            key.to_string(),
                            serde_json::Value::Number(serde_json::Number::from(val)),
                        );
                    }
                }
            } else if let Some(str_start) = after_key.find("<string>") {
                let str_content_start = str_start + 8;
                if let Some(str_end) = after_key[str_content_start..].find("</string>") {
                    let str_val = &after_key[str_content_start..str_content_start + str_end];
                    result.insert(
                        key.to_string(),
                        serde_json::Value::String(str_val.to_string()),
                    );
                }
            }

            remaining = &remaining[key_content_start + key_end..];
        } else {
            break;
        }
    }

    if result.is_empty() {
        None
    } else {
        Some(serde_json::Value::Object(result))
    }
}

fn parse_rfc2822_to_epoch(date_str: &str) -> Option<i64> {
    // Simple RFC 2822 date parsing for common formats
    // e.g., "Thu, 13 Feb 2025 14:30:00 -0500"
    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    let parts: Vec<&str> = date_str.split_whitespace().collect();
    if parts.len() < 5 {
        return None;
    }

    // Skip day-of-week if present
    let offset = if parts[0].ends_with(',') { 1 } else { 0 };
    if parts.len() < offset + 4 {
        return None;
    }

    let day: u32 = parts[offset].parse().ok()?;
    let month_str = parts[offset + 1];
    let month = months.iter().position(|&m| m == month_str)? as u32 + 1;
    let year: i32 = parts[offset + 2].parse().ok()?;
    let time_parts: Vec<&str> = parts[offset + 3].split(':').collect();
    if time_parts.len() < 3 {
        return None;
    }
    let hour: u32 = time_parts[0].parse().ok()?;
    let minute: u32 = time_parts[1].parse().ok()?;
    let second: u32 = time_parts[2].parse().ok()?;

    // Simple epoch calculation (approximate, doesn't account for leap seconds)
    let days_in_month = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    let mut days = (year as i64 - 1970) * 365;
    // Leap years
    days += ((year as i64 - 1) / 4) - (1969 / 4);
    days -= ((year as i64 - 1) / 100) - (1969 / 100);
    days += ((year as i64 - 1) / 400) - (1969 / 400);
    days += days_in_month.get(month as usize - 1).copied().unwrap_or(0) as i64;
    if month > 2 && (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)) {
        days += 1;
    }
    days += day as i64 - 1;

    let epoch = days * 86400 + hour as i64 * 3600 + minute as i64 * 60 + second as i64;

    // Apply timezone offset if present
    if let Some(tz_str) = parts.get(offset + 4) {
        if let Some(tz_offset) = parse_tz_offset(tz_str) {
            return Some(epoch - tz_offset);
        }
    }

    Some(epoch)
}

fn parse_tz_offset(tz: &str) -> Option<i64> {
    if tz.len() != 5 {
        return None;
    }
    let sign = match tz.as_bytes()[0] {
        b'+' => 1i64,
        b'-' => -1i64,
        _ => return None,
    };
    let hours: i64 = tz[1..3].parse().ok()?;
    let minutes: i64 = tz[3..5].parse().ok()?;
    Some(sign * (hours * 3600 + minutes * 60))
}
