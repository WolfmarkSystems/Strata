//! Zone.Identifier NTFS alternate data stream parser.
//!
//! Every file downloaded by a Mark-of-the-Web-aware application (modern
//! browsers, mail clients, messaging apps) carries a `:Zone.Identifier` ADS
//! with metadata about where the file came from. This parser decodes the
//! plaintext key=value format.

use crate::errors::ForensicError;

#[derive(Debug, Clone, Default)]
pub struct ZoneIdentifier {
    /// 0 = Local, 1 = Intranet, 2 = Trusted, 3 = Internet, 4 = Untrusted
    pub zone_id: u8,
    pub referrer_url: Option<String>,
    pub host_url: Option<String>,
    pub last_writer_package_name: Option<String>,
    pub app_zone_id: Option<u8>,
}

impl ZoneIdentifier {
    /// Parse a Zone.Identifier ADS (key=value text format, one per line).
    pub fn parse(bytes: &[u8]) -> Result<Self, ForensicError> {
        let owned: String;
        let text = match std::str::from_utf8(bytes) {
            Ok(s) => s,
            Err(_) => {
                let u16s: Vec<u16> = bytes
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                owned = String::from_utf16(&u16s).unwrap_or_default();
                &owned
            }
        };

        let mut out = ZoneIdentifier::default();

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('[') {
                continue;
            }
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            let k = k.trim();
            let v = v.trim();
            match k {
                "ZoneId" => {
                    if let Ok(z) = v.parse::<u8>() {
                        out.zone_id = z;
                    }
                }
                "ReferrerUrl" => out.referrer_url = Some(v.to_string()),
                "HostUrl" => out.host_url = Some(v.to_string()),
                "LastWriterPackageFamilyName" | "LastWriterPackageName" => {
                    out.last_writer_package_name = Some(v.to_string())
                }
                "AppZoneId" => {
                    if let Ok(z) = v.parse::<u8>() {
                        out.app_zone_id = Some(z);
                    }
                }
                _ => {}
            }
        }
        Ok(out)
    }

    pub fn zone_label(&self) -> &'static str {
        match self.zone_id {
            0 => "Local Computer",
            1 => "Local Intranet",
            2 => "Trusted",
            3 => "Internet",
            4 => "Untrusted/Restricted",
            _ => "Unknown",
        }
    }

    /// Is this file from an untrusted source? Zone 3 (Internet) and Zone 4
    /// (Untrusted/Restricted) mean Mark-of-the-Web applied.
    pub fn from_internet(&self) -> bool {
        self.zone_id >= 3
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_typical_zone_identifier() {
        let data = b"[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://example.com/\r\nHostUrl=https://example.com/file.exe\r\n";
        let z = ZoneIdentifier::parse(data).unwrap();
        assert_eq!(z.zone_id, 3);
        assert_eq!(z.referrer_url.as_deref(), Some("https://example.com/"));
        assert_eq!(z.host_url.as_deref(), Some("https://example.com/file.exe"));
        assert!(z.from_internet());
    }

    #[test]
    fn parses_zone_local() {
        let data = b"[ZoneTransfer]\r\nZoneId=0\r\n";
        let z = ZoneIdentifier::parse(data).unwrap();
        assert_eq!(z.zone_id, 0);
        assert!(!z.from_internet());
    }

    #[test]
    fn parses_last_writer_package_name() {
        let data = b"[ZoneTransfer]\r\nZoneId=3\r\nLastWriterPackageFamilyName=Microsoft.MicrosoftEdge_8wekyb3d8bbwe\r\n";
        let z = ZoneIdentifier::parse(data).unwrap();
        assert_eq!(z.zone_id, 3);
        assert_eq!(
            z.last_writer_package_name.as_deref(),
            Some("Microsoft.MicrosoftEdge_8wekyb3d8bbwe")
        );
    }

    #[test]
    fn zone_label_maps_correctly() {
        let z = ZoneIdentifier { zone_id: 3, ..Default::default() };
        assert_eq!(z.zone_label(), "Internet");
        let z2 = ZoneIdentifier { zone_id: 4, ..Default::default() };
        assert_eq!(z2.zone_label(), "Untrusted/Restricted");
        let z3 = ZoneIdentifier { zone_id: 1, ..Default::default() };
        assert_eq!(z3.zone_label(), "Local Intranet");
    }

    #[test]
    fn handles_empty_input() {
        let z = ZoneIdentifier::parse(b"").unwrap();
        assert_eq!(z.zone_id, 0);
        assert!(z.referrer_url.is_none());
        assert!(z.host_url.is_none());
    }

    #[test]
    fn handles_app_zone_id() {
        let data = b"[ZoneTransfer]\r\nZoneId=3\r\nAppZoneId=4\r\n";
        let z = ZoneIdentifier::parse(data).unwrap();
        assert_eq!(z.zone_id, 3);
        assert_eq!(z.app_zone_id, Some(4));
    }
}
