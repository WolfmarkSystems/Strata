//! setupapi.dev.log parser.
//!
//! The Windows device-install log records the first-ever connection of every
//! PnP device. For USB storage devices, this is the most authoritative
//! first-seen timestamp — more reliable than registry keys, which can be
//! cleared, because the log is append-only and rarely disturbed.

use crate::errors::ForensicError;

#[derive(Debug, Clone)]
pub struct SetupapiEntry {
    /// Device instance ID (e.g. "USB\\VID_0781&PID_5571\\12345")
    pub device_id: String,
    /// First-seen timestamp — LOCAL time, as a raw string (document the tz).
    pub timestamp: String,
    /// Section header context (install operation name)
    pub section: String,
}

pub struct SetupapiParser;

impl SetupapiParser {
    /// Parse a setupapi.dev.log file into a Vec of device install entries.
    pub fn parse(text: &str) -> Result<Vec<SetupapiEntry>, ForensicError> {
        let mut out = Vec::new();
        let mut current_section = String::new();
        let _ = &current_section;
        let mut current_timestamp = String::new();

        // The log alternates between:
        //   >>>  [Device Install (Hardware initiated) - USB\VID_..&PID_..\SERIAL]
        //   >>>  Section start 2024/01/15 09:22:14.312
        //   ... body lines ...
        //   <<<  Section end 2024/01/15 09:22:14.450
        for line in text.lines() {
            let line = line.trim_end();
            if let Some(rest) = line.strip_prefix(">>>  [") {
                if let Some(end) = rest.rfind(']') {
                    let section_text = &rest[..end];
                    current_section = section_text.to_string();
                    // Look for a USB device id
                    if let Some(dev_start) = section_text.find("USB") {
                        let dev_id = section_text[dev_start..].trim_end_matches(']').to_string();
                        // Timestamp is captured on the next ">>>  Section start" line;
                        // commit once we see it.
                        out.push(SetupapiEntry {
                            device_id: dev_id,
                            timestamp: current_timestamp.clone(),
                            section: current_section.clone(),
                        });
                    }
                }
            } else if let Some(rest) = line.strip_prefix(">>>  Section start ") {
                current_timestamp = rest.trim().to_string();
                // Update the most-recently-pushed entry's timestamp if it is empty.
                if let Some(last) = out.last_mut() {
                    if last.timestamp.is_empty() {
                        last.timestamp = current_timestamp.clone();
                    }
                }
            }
        }

        Ok(out)
    }

    /// Find the first-ever connection timestamp for a specific USB device serial.
    pub fn first_connection(text: &str, serial: &str) -> Option<String> {
        let entries = Self::parse(text).ok()?;
        entries
            .into_iter()
            .find(|e| e.device_id.contains(serial))
            .map(|e| e.timestamp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_section() {
        let log = r#">>>  [Device Install (Hardware initiated) - USB\VID_0781&PID_5571\1234567]
>>>  Section start 2024/01/15 09:22:14.312
     dvi: ...body...
<<<  Section end 2024/01/15 09:22:14.450
"#;
        let entries = SetupapiParser::parse(log).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].device_id.contains("VID_0781"));
        assert!(entries[0].timestamp.contains("2024/01/15"));
    }
}
