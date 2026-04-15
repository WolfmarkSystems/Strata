//! Parser for the NTFS `Zone.Identifier` Alternate Data Stream.
//!
//! Windows tags every file downloaded from a non-`Trusted` location
//! with a `:Zone.Identifier` ADS containing INI-style key/value pairs
//! that record where the file came from. This is the
//! **Mark-of-the-Web** (MOTW) — Office, Defender, SmartScreen, and
//! PowerShell all gate behaviour on its presence.
//!
//! Forensically, the ADS is a goldmine: it gives the original source
//! URL, the host that served the file, and (post-Win10 1809) the
//! external IP address of that host. Adversaries who delete the
//! source file but forget to scrub the ADS leave a complete download-
//! provenance trail.
//!
//! ## Format
//!
//! Plain UTF-8 (or UTF-16LE with BOM) text:
//!
//! ```text
//! [ZoneTransfer]
//! ZoneId=3
//! ReferrerUrl=https://attacker.example/landing
//! HostUrl=https://cdn.attacker.example/payload.exe
//! HostIpAddress=203.0.113.42
//! ```
//!
//! Real-world ADSes vary in casing, line endings, BOMs, and key
//! presence — only `ZoneId` is required. This parser tolerates all of
//! that.
//!
//! ## Zone ID values
//!
//! | ID | Name | Forensic meaning |
//! |---|---|---|
//! | 0  | LocalMachine | File originated on this machine |
//! | 1  | Intranet     | Local-network share / domain HTTP |
//! | 2  | Trusted      | Site explicitly added to Trusted Sites |
//! | 3  | Internet     | Public web — typical download source |
//! | 4  | Untrusted    | Restricted Sites / explicit block list |
//!
//! ## MITRE ATT&CK
//! * **T1566** (Phishing) — `zone_id >= 3` indicates the file came
//!   from outside the local trust boundary, the canonical phishing-
//!   payload delivery vector.
//! * **T1105** (Ingress Tool Transfer) — when `host_url` is populated,
//!   the ADS records the exact tool-transfer endpoint.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println` per CLAUDE.md.

use strata_plugin_sdk::Artifact;

/// One typed `Zone.Identifier` ADS.
///
/// Every field is forensic-meaning-first; downstream consumers
/// (Phantom, Trace, Sigma rules, the timeline view) read these
/// without having to re-parse INI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneIdentifier {
    /// Numeric Internet Explorer security zone the file came from.
    /// 0 = LocalMachine, 1 = Intranet, 2 = Trusted, 3 = Internet,
    /// 4 = Untrusted. Values >= 3 cross the trust boundary;
    /// SmartScreen and Office Protected View key on this field.
    /// Stored as `u8` because Windows itself only ever writes
    /// single-digit values.
    pub zone_id: u8,

    /// Human-readable label derived from `zone_id` via
    /// [`zone_name_for`]. Stored separately so consumers don't repeat
    /// the lookup when filtering or reporting.
    pub zone_name: &'static str,

    /// The `ReferrerUrl=` value — the page that linked to the
    /// download. Equivalent to a Referer HTTP header preserved on
    /// disk. `None` when the field is absent (older browsers, direct
    /// downloads, BITS jobs, etc.).
    pub referring_url: Option<String>,

    /// The `HostUrl=` value — the actual URL the file was fetched
    /// from. This is the highest-signal field for incident response:
    /// it answers "what server delivered this binary". `None` for
    /// non-HTTP transfers (SMB shares, USB).
    pub host_url: Option<String>,

    /// The `HostIpAddress=` value — IP of the host that served the
    /// file. Added in Win10 1809; not present on earlier OSes or for
    /// non-HTTP transfers. Pair with `host_url` to defeat domain-
    /// flipping fast-flux infrastructure.
    pub host_ip_address: Option<String>,
}

impl ZoneIdentifier {
    /// Convenience: `true` when the file crossed the local trust
    /// boundary (Internet or Untrusted zones). Equivalent to
    /// `self.zone_id >= 3`.
    pub fn from_internet(&self) -> bool {
        self.zone_id >= 3
    }
}

/// Map a numeric Zone ID to its canonical Microsoft label.
pub fn zone_name_for(zone_id: u8) -> &'static str {
    match zone_id {
        0 => "LocalMachine",
        1 => "Intranet",
        2 => "Trusted",
        3 => "Internet",
        4 => "Untrusted",
        _ => "Unknown",
    }
}

/// Parse a `Zone.Identifier` ADS body.
///
/// Returns `Some(ZoneIdentifier)` on success, `None` when the body
/// does not contain a parseable `ZoneId=` value. Tolerates BOMs
/// (UTF-8 / UTF-16LE / UTF-16BE), mixed CR/LF line endings, key-name
/// casing, and arbitrary whitespace around `=`.
pub fn parse(bytes: &[u8]) -> Option<ZoneIdentifier> {
    let text = decode_text(bytes);

    // Walk the body line by line, collecting key/value pairs from any
    // `[ZoneTransfer]` (case-insensitive) section. Accept keys
    // outside a section too — a few sloppy downloaders omit the
    // header.
    let mut in_zone_section = true;
    let mut zone_id: Option<u8> = None;
    let mut referring_url: Option<String> = None;
    let mut host_url: Option<String> = None;
    let mut host_ip: Option<String> = None;

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        if let Some(section) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            in_zone_section = section.trim().eq_ignore_ascii_case("ZoneTransfer");
            continue;
        }
        if !in_zone_section {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim().trim_matches('"');
        if value.is_empty() {
            continue;
        }
        if key.eq_ignore_ascii_case("ZoneId") {
            // Tolerate "3", "0x3", or trailing whitespace / comments.
            let cleaned = value
                .split(|c: char| c.is_whitespace() || c == ';')
                .next()
                .unwrap_or(value);
            if let Some(stripped) = cleaned
                .strip_prefix("0x")
                .or_else(|| cleaned.strip_prefix("0X"))
            {
                if let Ok(n) = u8::from_str_radix(stripped, 16) {
                    zone_id = Some(n);
                }
            } else if let Ok(n) = cleaned.parse::<u8>() {
                zone_id = Some(n);
            }
        } else if key.eq_ignore_ascii_case("ReferrerUrl")
            || key.eq_ignore_ascii_case("ReferringUrl")
        {
            // Microsoft has used both spellings across versions.
            referring_url = Some(value.to_string());
        } else if key.eq_ignore_ascii_case("HostUrl") {
            host_url = Some(value.to_string());
        } else if key.eq_ignore_ascii_case("HostIpAddress") {
            host_ip = Some(value.to_string());
        }
    }

    let zone_id = zone_id?;
    Some(ZoneIdentifier {
        zone_id,
        zone_name: zone_name_for(zone_id),
        referring_url,
        host_url,
        host_ip_address: host_ip,
    })
}

/// Build a plugin-SDK `Artifact` from a parsed `ZoneIdentifier`.
///
/// MITRE mapping (per the user-facing schema):
///   * `mitre = T1566` when `zone_id >= 3` (cross-boundary phishing).
///   * `mitre_secondary = T1105` when `host_url` is populated and
///     `zone_id >= 3`. Otherwise, when `host_url` is populated and
///     no phishing-zone primary exists, T1105 takes the primary slot.
///   * `forensic_value = High` when `zone_id >= 3`, else `Low`.
pub fn to_artifact(zi: &ZoneIdentifier, source: &str) -> Artifact {
    let mut a = Artifact::new("Zone Identifier", source);
    a.add_field(
        "title",
        &format!("Zone.Identifier: {} (zone {})", zi.zone_name, zi.zone_id),
    );
    let mut detail = format!("Zone: {} ({})", zi.zone_name, zi.zone_id);
    if let Some(u) = &zi.referring_url {
        detail.push_str(&format!(" | Referrer: {}", u));
    }
    if let Some(u) = &zi.host_url {
        detail.push_str(&format!(" | Host: {}", u));
    }
    if let Some(ip) = &zi.host_ip_address {
        detail.push_str(&format!(" | IP: {}", ip));
    }
    a.add_field("detail", &detail);
    a.add_field("file_type", "Zone Identifier");
    a.add_field("zone_id", &zi.zone_id.to_string());
    a.add_field("zone_name", zi.zone_name);
    if let Some(u) = &zi.referring_url {
        a.add_field("referring_url", u);
    }
    if let Some(u) = &zi.host_url {
        a.add_field("host_url", u);
    }
    if let Some(ip) = &zi.host_ip_address {
        a.add_field("host_ip_address", ip);
    }
    if zi.zone_id >= 3 {
        a.add_field("mitre", "T1566");
        if zi.host_url.is_some() {
            a.add_field("mitre_secondary", "T1105");
        }
        a.add_field("forensic_value", "High");
        a.add_field("suspicious", "true");
    } else {
        if zi.host_url.is_some() {
            a.add_field("mitre", "T1105");
        }
        a.add_field("forensic_value", "Low");
    }
    a
}

/// Decode the ADS text. Handles UTF-8, UTF-8 BOM, UTF-16LE BOM,
/// UTF-16BE BOM, and raw ASCII. Falls back to lossy UTF-8 conversion
/// for anything else.
fn decode_text(bytes: &[u8]) -> String {
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return String::from_utf8_lossy(&bytes[3..]).into_owned();
    }
    if bytes.starts_with(&[0xFF, 0xFE]) {
        let body = &bytes[2..];
        let u16s: Vec<u16> = body
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        return String::from_utf16_lossy(&u16s);
    }
    if bytes.starts_with(&[0xFE, 0xFF]) {
        let body = &bytes[2..];
        let u16s: Vec<u16> = body
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        return String::from_utf16_lossy(&u16s);
    }
    String::from_utf8_lossy(bytes).into_owned()
}

// ── tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_returns_none_for_empty_input() {
        assert!(parse(&[]).is_none());
    }

    #[test]
    fn parse_returns_none_when_zoneid_missing() {
        let body = b"[ZoneTransfer]\nReferrerUrl=https://example.com/\n";
        assert!(parse(body).is_none());
    }

    #[test]
    fn parse_extracts_full_zone_transfer_block() {
        let body = b"[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://attacker.example/landing\r\nHostUrl=https://cdn.attacker.example/payload.exe\r\nHostIpAddress=203.0.113.42\r\n";
        let zi = parse(body).expect("must parse");
        assert_eq!(zi.zone_id, 3);
        assert_eq!(zi.zone_name, "Internet");
        assert_eq!(zi.referring_url.as_deref(), Some("https://attacker.example/landing"));
        assert_eq!(zi.host_url.as_deref(), Some("https://cdn.attacker.example/payload.exe"));
        assert_eq!(zi.host_ip_address.as_deref(), Some("203.0.113.42"));
        assert!(zi.from_internet());
    }

    #[test]
    fn parse_handles_utf8_bom() {
        let mut body: Vec<u8> = vec![0xEF, 0xBB, 0xBF];
        body.extend_from_slice(b"[ZoneTransfer]\nZoneId=3\n");
        let zi = parse(&body).expect("must parse with BOM");
        assert_eq!(zi.zone_id, 3);
    }

    #[test]
    fn parse_handles_utf16le_bom() {
        let text = "[ZoneTransfer]\nZoneId=4\nHostUrl=https://evil/\n";
        let mut body: Vec<u8> = vec![0xFF, 0xFE];
        for u in text.encode_utf16() {
            body.extend_from_slice(&u.to_le_bytes());
        }
        let zi = parse(&body).expect("must parse UTF-16LE");
        assert_eq!(zi.zone_id, 4);
        assert_eq!(zi.zone_name, "Untrusted");
        assert_eq!(zi.host_url.as_deref(), Some("https://evil/"));
    }

    #[test]
    fn parse_tolerates_case_insensitive_keys_and_quoting() {
        let body = b"[zonetransfer]\nzoneid = 2\nhosturl = \"https://trusted.example/installer.msi\"\n";
        let zi = parse(body).expect("must parse case-insensitively");
        assert_eq!(zi.zone_id, 2);
        assert_eq!(zi.zone_name, "Trusted");
        assert_eq!(
            zi.host_url.as_deref(),
            Some("https://trusted.example/installer.msi")
        );
    }

    #[test]
    fn parse_accepts_hex_zoneid() {
        let body = b"[ZoneTransfer]\nZoneId=0x3\n";
        let zi = parse(body).expect("must parse hex");
        assert_eq!(zi.zone_id, 3);
    }

    #[test]
    fn parse_accepts_referrerurl_alternate_spelling() {
        let body = b"[ZoneTransfer]\nZoneId=3\nReferringUrl=https://landing/\n";
        let zi = parse(body).expect("must parse");
        assert_eq!(zi.referring_url.as_deref(), Some("https://landing/"));
    }

    #[test]
    fn zone_name_for_known_values() {
        assert_eq!(zone_name_for(0), "LocalMachine");
        assert_eq!(zone_name_for(1), "Intranet");
        assert_eq!(zone_name_for(2), "Trusted");
        assert_eq!(zone_name_for(3), "Internet");
        assert_eq!(zone_name_for(4), "Untrusted");
        assert_eq!(zone_name_for(99), "Unknown");
    }

    #[test]
    fn to_artifact_emits_t1566_plus_t1105_for_internet_with_host() {
        let zi = ZoneIdentifier {
            zone_id: 3,
            zone_name: zone_name_for(3),
            referring_url: None,
            host_url: Some("https://evil/p.exe".to_string()),
            host_ip_address: None,
        };
        let a = to_artifact(&zi, "/evid/x.exe:Zone.Identifier");
        assert_eq!(a.data.get("zone_id").map(String::as_str), Some("3"));
        assert_eq!(a.data.get("zone_name").map(String::as_str), Some("Internet"));
        assert_eq!(a.data.get("mitre").map(String::as_str), Some("T1566"));
        assert_eq!(
            a.data.get("mitre_secondary").map(String::as_str),
            Some("T1105")
        );
        assert_eq!(a.data.get("forensic_value").map(String::as_str), Some("High"));
        assert_eq!(a.data.get("suspicious").map(String::as_str), Some("true"));
    }

    #[test]
    fn to_artifact_emits_t1566_only_for_internet_without_host() {
        let zi = ZoneIdentifier {
            zone_id: 3,
            zone_name: zone_name_for(3),
            referring_url: None,
            host_url: None,
            host_ip_address: None,
        };
        let a = to_artifact(&zi, "/evid/x.exe:Zone.Identifier");
        assert_eq!(a.data.get("mitre").map(String::as_str), Some("T1566"));
        assert!(!a.data.contains_key("mitre_secondary"));
        assert_eq!(a.data.get("forensic_value").map(String::as_str), Some("High"));
    }

    #[test]
    fn to_artifact_uses_t1105_as_primary_when_no_phishing_zone() {
        let zi = ZoneIdentifier {
            zone_id: 1,
            zone_name: zone_name_for(1),
            referring_url: None,
            host_url: Some("https://internal/share.exe".to_string()),
            host_ip_address: None,
        };
        let a = to_artifact(&zi, "/evid/x.exe:Zone.Identifier");
        assert_eq!(a.data.get("mitre").map(String::as_str), Some("T1105"));
        assert!(!a.data.contains_key("mitre_secondary"));
        assert_eq!(a.data.get("forensic_value").map(String::as_str), Some("Low"));
        assert!(!a.data.contains_key("suspicious"));
    }

    #[test]
    fn to_artifact_emits_low_severity_for_intranet() {
        let zi = ZoneIdentifier {
            zone_id: 1,
            zone_name: zone_name_for(1),
            referring_url: None,
            host_url: None,
            host_ip_address: None,
        };
        let a = to_artifact(&zi, "/evid/internal.docx:Zone.Identifier");
        assert_eq!(a.data.get("forensic_value").map(String::as_str), Some("Low"));
        assert!(!a.data.contains_key("mitre"));
    }

    #[test]
    fn parse_ignores_comments_and_blank_lines() {
        let body = b"; comment line\n\n[ZoneTransfer]\n# also comment\nZoneId=3\n\n";
        let zi = parse(body).expect("must parse");
        assert_eq!(zi.zone_id, 3);
    }

    #[test]
    fn from_internet_threshold_is_three() {
        for z in 0u8..=2 {
            let zi = ZoneIdentifier {
                zone_id: z,
                zone_name: zone_name_for(z),
                referring_url: None,
                host_url: None,
                host_ip_address: None,
            };
            assert!(!zi.from_internet(), "zone {} must not be from_internet", z);
        }
        for z in 3u8..=4 {
            let zi = ZoneIdentifier {
                zone_id: z,
                zone_name: zone_name_for(z),
                referring_url: None,
                host_url: None,
                host_ip_address: None,
            };
            assert!(zi.from_internet(), "zone {} must be from_internet", z);
        }
    }
}
