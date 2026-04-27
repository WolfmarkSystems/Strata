//! DNS query logs and IDS alert parsers (X-1).
//!
//! Covers three DNS log formats and two IDS alert formats:
//!
//! * **BIND `named` query log** — space-delimited plaintext, one query per
//!   line.
//! * **Windows DNS debug log** — space-delimited; timestamp + direction +
//!   peer IP + query class/type + domain.
//! * **mDNSResponder via Unified Log** — caller-constructed; wired later
//!   by consumers that have decoded a tracev3 file.
//! * **Snort fast-alert** — bracketed priority / classification tokens.
//! * **Suricata `eve.json`** — one JSON object per line; we decode the
//!   `event_type == "alert"` lines into typed records.
//!
//! ## MITRE ATT&CK
//! * **T1071.004** — DNS (Application Layer Protocol: DNS).
//! * IDS rule classification drives per-alert mapping; we fall back to
//!   T1071 when the rule carries no explicit mapping.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, NaiveDate, NaiveDateTime, TimeZone, Utc};
use std::path::Path;

// ── DNS ──────────────────────────────────────────────────────────────────

/// Which on-disk format a DNS record came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsLogFormat {
    /// BIND `named.log` — `client @0x... 1.2.3.4#port (domain): query: domain IN A +`.
    Bind,
    /// Windows DNS server debug log — space-delimited.
    WindowsDns,
    /// mDNSResponder via the macOS Unified Log pipeline.
    MDNSResponder,
}

impl DnsLogFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            DnsLogFormat::Bind => "BIND",
            DnsLogFormat::WindowsDns => "WindowsDNS",
            DnsLogFormat::MDNSResponder => "MDNSResponder",
        }
    }
}

/// One DNS query extracted from a log file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuery {
    /// UTC timestamp of the query.
    pub timestamp: DateTime<Utc>,
    /// Resolver client IP (BIND) or peer IP (Windows) when present.
    pub client_ip: Option<String>,
    /// Queried FQDN. Always populated.
    pub query_name: String,
    /// Query type (`A`, `AAAA`, `MX`, …).
    pub query_type: String,
    /// Response code string if the line captured one (`NOERROR`, `NXDOMAIN`).
    pub response_code: Option<String>,
    /// Any response IPs surfaced on the line.
    pub response_ip: Vec<String>,
    /// Source log format.
    pub log_format: DnsLogFormat,
}

/// Parse an entire DNS log body by auto-detecting the format line by
/// line. Lines that match neither format are skipped. Empty lines are
/// ignored. Never panics.
pub fn parse_dns_log(contents: &str) -> Vec<DnsQuery> {
    let mut out = Vec::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(q) = parse_bind_line(line) {
            out.push(q);
            continue;
        }
        if let Some(q) = parse_windows_dns_line(line) {
            out.push(q);
            continue;
        }
    }
    out
}

/// Parse one BIND query-log line. Returns `None` for non-matching
/// lines.
///
/// Expected shape (whitespace separated):
/// `DD-MMM-YYYY HH:MM:SS.sss client @0x... 1.2.3.4#53 (domain): query: domain IN A +...`
pub fn parse_bind_line(line: &str) -> Option<DnsQuery> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 10 {
        return None;
    }
    // Pattern landmarks.
    let client_idx = parts.iter().position(|t| *t == "client")?;
    let query_idx = parts.iter().position(|t| *t == "query:")?;
    if query_idx + 3 >= parts.len() {
        return None;
    }
    let peer_token = parts.get(client_idx + 2)?;
    let (ip, _port) = split_host_port(peer_token);
    let query_name = parts.get(query_idx + 1)?.trim_end_matches('.').to_string();
    let query_class = parts.get(query_idx + 2)?.to_string();
    let query_type = parts.get(query_idx + 3)?.to_string();
    if query_class != "IN" {
        return None;
    }
    let ts = parse_bind_timestamp(parts.first()?, parts.get(1)?)?;
    Some(DnsQuery {
        timestamp: ts,
        client_ip: Some(ip),
        query_name,
        query_type,
        response_code: None,
        response_ip: Vec::new(),
        log_format: DnsLogFormat::Bind,
    })
}

fn parse_bind_timestamp(date_tok: &str, time_tok: &str) -> Option<DateTime<Utc>> {
    let combined = format!("{} {}", date_tok, time_tok);
    // Try with milliseconds first, then without.
    for fmt in ["%d-%b-%Y %H:%M:%S%.f", "%d-%b-%Y %H:%M:%S"] {
        if let Ok(ndt) = NaiveDateTime::parse_from_str(&combined, fmt) {
            return Some(Utc.from_utc_datetime(&ndt));
        }
    }
    None
}

fn split_host_port(token: &str) -> (String, Option<u16>) {
    if let Some((h, p)) = token.rsplit_once('#') {
        return (h.to_string(), p.parse::<u16>().ok());
    }
    (token.to_string(), None)
}

/// Parse one Windows DNS debug-log line. Windows DNS log shape:
/// `1/1/2026 12:00:00 PM 0A00 PACKET 0000... UDP Rcv 1.2.3.4 1234 R Q [...] A domain`
pub fn parse_windows_dns_line(line: &str) -> Option<DnsQuery> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 11 {
        return None;
    }
    if parts.get(4).copied() != Some("PACKET") {
        return None;
    }
    // Timestamp: "MM/DD/YYYY HH:MM:SS AM/PM" (parts[0..3] joined).
    let ts_str = format!("{} {} {}", parts[0], parts[1], parts[2]);
    let ts = parse_windows_dns_ts(&ts_str)?;
    // Query name is the last whitespace token; the line ends with
    // encoded domain like "(7)example(3)com(0)". We normalize.
    let query_name_raw = parts.last()?.to_string();
    let query_name = decode_windows_dns_name(&query_name_raw);
    // Peer IP: first token after "UDP" / "TCP" + direction ("Rcv"/"Snd").
    let mut client_ip: Option<String> = None;
    if let Some(dir_idx) = parts.iter().position(|t| *t == "Rcv" || *t == "Snd") {
        if let Some(ip_tok) = parts.get(dir_idx + 1) {
            client_ip = Some(ip_tok.to_string());
        }
    }
    // Query type token: second-to-last token is typically record type
    // ("A", "AAAA", "MX"…).
    let query_type = parts
        .get(parts.len().saturating_sub(2))
        .map(|s| s.to_string())
        .unwrap_or_else(|| "A".to_string());
    Some(DnsQuery {
        timestamp: ts,
        client_ip,
        query_name,
        query_type,
        response_code: None,
        response_ip: Vec::new(),
        log_format: DnsLogFormat::WindowsDns,
    })
}

fn parse_windows_dns_ts(s: &str) -> Option<DateTime<Utc>> {
    for fmt in [
        "%m/%d/%Y %I:%M:%S %p",
        "%m/%d/%Y %H:%M:%S",
        "%-m/%-d/%Y %I:%M:%S %p",
    ] {
        if let Ok(ndt) = NaiveDateTime::parse_from_str(s, fmt) {
            return Some(Utc.from_utc_datetime(&ndt));
        }
    }
    None
}

/// Decode a Windows DNS debug-log encoded name such as
/// `"(7)example(3)com(0)"` into `"example.com"`. Leaves already-plain
/// names unchanged.
pub fn decode_windows_dns_name(encoded: &str) -> String {
    if !encoded.starts_with('(') {
        return encoded.trim_end_matches('.').to_string();
    }
    let mut out = String::new();
    let mut rest = encoded;
    while let Some(open) = rest.find('(') {
        if let Some(close) = rest[open..].find(')') {
            let after = &rest[open + close + 1..];
            // Label text between this ')' and the next '('.
            let next_open = after.find('(').unwrap_or(after.len());
            let label = &after[..next_open];
            if !label.is_empty() {
                if !out.is_empty() {
                    out.push('.');
                }
                out.push_str(label);
            }
            rest = &after[next_open..];
        } else {
            break;
        }
    }
    out
}

// ── IDS (Snort / Suricata) ───────────────────────────────────────────────

/// Which IDS alert format produced the record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdsAlertFormat {
    /// Snort / Suricata fast alert format (`alert.fast`).
    SnortFast,
    /// Suricata `eve.json` (one JSON object per line).
    SuricataEve,
}

impl IdsAlertFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            IdsAlertFormat::SnortFast => "SnortFast",
            IdsAlertFormat::SuricataEve => "SuricataEve",
        }
    }
}

/// One IDS alert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdsAlert {
    /// Alert timestamp in UTC.
    pub timestamp: DateTime<Utc>,
    /// Alert rule signature / message.
    pub signature: String,
    /// Rule classification (`ET SCAN`, `Potentially Bad Traffic`, …).
    pub classification: Option<String>,
    /// Priority / severity (1 = highest).
    pub priority: Option<i64>,
    /// GID:SID:REV triple concatenated as `gid:sid:rev`.
    pub rule_id: Option<String>,
    /// L4 protocol (`TCP`, `UDP`, `ICMP`).
    pub protocol: Option<String>,
    /// Source IP (string form to cover IPv4 and IPv6).
    pub src_ip: Option<String>,
    /// Source port.
    pub src_port: Option<u16>,
    /// Destination IP.
    pub dst_ip: Option<String>,
    /// Destination port.
    pub dst_port: Option<u16>,
    /// Format of origin.
    pub format: IdsAlertFormat,
}

/// Parse an entire IDS alert log. Tries Snort-fast first then Suricata
/// JSON (one line per record). Unparseable lines are skipped.
pub fn parse_ids_log(contents: &str) -> Vec<IdsAlert> {
    let mut out = Vec::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('{') {
            if let Some(a) = parse_suricata_eve_line(line) {
                out.push(a);
                continue;
            }
        }
        if let Some(a) = parse_snort_fast_line(line) {
            out.push(a);
        }
    }
    out
}

/// Parse a Snort fast-alert line:
/// `MM/DD-HH:MM:SS.ffffff  [**] [1:2001:1] ET SCAN ... [**] [Classification: ...] [Priority: 1] {TCP} 1.2.3.4:80 -> 5.6.7.8:443`
pub fn parse_snort_fast_line(line: &str) -> Option<IdsAlert> {
    // Timestamp is the first whitespace-separated token.
    let mut cursor = line.trim();
    let (ts_tok, rest) = cursor.split_once(char::is_whitespace)?;
    cursor = rest.trim_start();
    let timestamp = parse_snort_ts(ts_tok).unwrap_or_else(unix_epoch);
    // Expect leading [**].
    let cursor = cursor.strip_prefix("[**]")?.trim_start();
    // Rule id in [gid:sid:rev].
    let (rule_id, cursor) = take_bracketed(cursor)?;
    let cursor = cursor.trim_start();
    // Signature up to the next "[**]".
    let sig_end = cursor.find("[**]").unwrap_or(cursor.len());
    let signature = cursor[..sig_end].trim().to_string();
    let after_sig = if sig_end < cursor.len() {
        cursor[sig_end + 4..].trim_start()
    } else {
        ""
    };
    // Classification + priority.
    let mut classification: Option<String> = None;
    let mut priority: Option<i64> = None;
    let mut tail = after_sig;
    while let Some((bracketed, rest)) = take_bracketed(tail) {
        if let Some(c) = bracketed.strip_prefix("Classification:") {
            classification = Some(c.trim().to_string());
        } else if let Some(p) = bracketed.strip_prefix("Priority:") {
            priority = p.trim().parse::<i64>().ok();
        }
        tail = rest.trim_start();
        if !tail.starts_with('[') {
            break;
        }
    }
    // Protocol + endpoints.
    let (protocol, mut tail) = if let Some(rest) = tail.strip_prefix('{') {
        if let Some((proto, rem)) = rest.split_once('}') {
            (Some(proto.trim().to_string()), rem.trim_start())
        } else {
            (None, tail)
        }
    } else {
        (None, tail)
    };
    let mut src_ip: Option<String> = None;
    let mut src_port: Option<u16> = None;
    let mut dst_ip: Option<String> = None;
    let mut dst_port: Option<u16> = None;
    if let Some(arrow) = tail.find("->") {
        let left = tail[..arrow].trim();
        let right = tail[arrow + 2..].trim();
        if let Some((l_ip, l_port)) = left.rsplit_once(':') {
            src_ip = Some(l_ip.trim().to_string());
            src_port = l_port.trim().parse::<u16>().ok();
        }
        if let Some((r_ip, r_port)) = right.rsplit_once(':') {
            dst_ip = Some(r_ip.trim().to_string());
            dst_port = r_port.trim().parse::<u16>().ok();
        }
        tail = "";
    }
    let _ = tail;
    Some(IdsAlert {
        timestamp,
        signature,
        classification,
        priority,
        rule_id: Some(rule_id),
        protocol,
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        format: IdsAlertFormat::SnortFast,
    })
}

fn unix_epoch() -> DateTime<Utc> {
    DateTime::<Utc>::from(std::time::UNIX_EPOCH)
}

fn take_bracketed(s: &str) -> Option<(String, &str)> {
    let s = s.trim_start();
    let rest = s.strip_prefix('[')?;
    let end = rest.find(']')?;
    Some((rest[..end].trim().to_string(), &rest[end + 1..]))
}

fn parse_snort_ts(tok: &str) -> Option<DateTime<Utc>> {
    // `MM/DD-HH:MM:SS.ffffff` — no year; assume current Unix year.
    let this_year = Utc::now().date_naive().year_ce().1 as i32;
    let (date_part, time_part) = tok.split_once('-')?;
    let (month_str, day_str) = date_part.split_once('/')?;
    let month: u32 = month_str.parse().ok()?;
    let day: u32 = day_str.parse().ok()?;
    let date = NaiveDate::from_ymd_opt(this_year, month, day)?;
    for fmt in ["%H:%M:%S%.f", "%H:%M:%S"] {
        if let Ok(t) = chrono::NaiveTime::parse_from_str(time_part, fmt) {
            return Some(Utc.from_utc_datetime(&date.and_time(t)));
        }
    }
    None
}

use chrono::Datelike;

/// Parse one Suricata `eve.json` line. Returns `None` for lines that
/// do not carry `event_type == "alert"` or cannot be decoded.
pub fn parse_suricata_eve_line(line: &str) -> Option<IdsAlert> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    if v.get("event_type").and_then(|x| x.as_str()) != Some("alert") {
        return None;
    }
    let ts_raw = v.get("timestamp").and_then(|x| x.as_str()).unwrap_or("");
    let timestamp = DateTime::parse_from_rfc3339(ts_raw)
        .map(|dt| dt.with_timezone(&Utc))
        .ok()
        .or_else(|| {
            // Suricata also emits `%Y-%m-%dT%H:%M:%S.%6f%z` without the
            // colon in the offset — try that.
            DateTime::parse_from_str(ts_raw, "%Y-%m-%dT%H:%M:%S%.f%z")
                .map(|dt| dt.with_timezone(&Utc))
                .ok()
        })
        .unwrap_or_else(unix_epoch);
    let alert = v.get("alert")?;
    let signature = alert
        .get("signature")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let classification = alert
        .get("category")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string());
    let priority = alert.get("severity").and_then(|x| x.as_i64());
    let gid = alert.get("gid").and_then(|x| x.as_i64()).unwrap_or(0);
    let sid = alert
        .get("signature_id")
        .and_then(|x| x.as_i64())
        .unwrap_or(0);
    let rev = alert.get("rev").and_then(|x| x.as_i64()).unwrap_or(0);
    let rule_id = Some(format!("{}:{}:{}", gid, sid, rev));
    Some(IdsAlert {
        timestamp,
        signature,
        classification,
        priority,
        rule_id,
        protocol: v
            .get("proto")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string()),
        src_ip: v
            .get("src_ip")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string()),
        src_port: v.get("src_port").and_then(|x| x.as_u64()).map(|n| n as u16),
        dst_ip: v
            .get("dest_ip")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string()),
        dst_port: v
            .get("dest_port")
            .and_then(|x| x.as_u64())
            .map(|n| n as u16),
        format: IdsAlertFormat::SuricataEve,
    })
}

/// File-classifier helper for routing. Returns the DNS/IDS flavour a
/// filename suggests, or `None` if this module does not own the path.
pub fn classify_file(path: &Path) -> Option<DnsOrIds> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let full = path.to_string_lossy().to_ascii_lowercase();
    if name == "eve.json" || name.ends_with(".eve.json") {
        return Some(DnsOrIds::IdsEve);
    }
    if name == "alert.fast" || name.ends_with(".alert") || name == "fast.log" {
        return Some(DnsOrIds::IdsSnortFast);
    }
    if name == "named.log" || name.ends_with(".named.log") || name == "query.log" {
        return Some(DnsOrIds::DnsBind);
    }
    if name.starts_with("dns") && name.ends_with(".log") && full.contains("windows") {
        return Some(DnsOrIds::DnsWindows);
    }
    if name == "dns.log" {
        return Some(DnsOrIds::DnsBind);
    }
    None
}

/// Routing tag used by the Netflow plugin to dispatch a matched file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsOrIds {
    DnsBind,
    DnsWindows,
    IdsSnortFast,
    IdsEve,
}

// ── MITRE helpers ────────────────────────────────────────────────────────

pub fn mitre_for_ids(classification: Option<&str>) -> &'static str {
    match classification.map(|s| s.to_ascii_lowercase()) {
        Some(c) if c.contains("scan") => "T1595",
        Some(c) if c.contains("trojan") || c.contains("malware") => "T1071",
        Some(c) if c.contains("exploit") => "T1190",
        Some(c) if c.contains("policy") => "T1071",
        _ => "T1071",
    }
}

// ── tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bind_query_line() {
        let line = "01-Jun-2024 12:00:00.123 client @0x7f8 192.0.2.15#54321 (example.com): query: example.com IN A +E(0)K (192.0.2.1)";
        let q = parse_bind_line(line).expect("bind parses");
        assert_eq!(q.query_name, "example.com");
        assert_eq!(q.query_type, "A");
        assert_eq!(q.client_ip.as_deref(), Some("192.0.2.15"));
        assert_eq!(q.log_format, DnsLogFormat::Bind);
        assert_eq!(q.timestamp.timestamp(), 1_717_243_200);
    }

    #[test]
    fn parse_windows_dns_line_decodes_name() {
        let line = "6/1/2024 12:00:00 PM 0A00 PACKET 0000000000000000 UDP Rcv 192.0.2.25  1234 R Q [0001 D NOERROR] A      (7)example(3)com(0)";
        let q = parse_windows_dns_line(line).expect("windows dns parses");
        assert_eq!(q.query_name, "example.com");
        assert_eq!(q.client_ip.as_deref(), Some("192.0.2.25"));
        assert_eq!(q.log_format, DnsLogFormat::WindowsDns);
    }

    #[test]
    fn decode_windows_dns_name_plain_and_encoded() {
        assert_eq!(decode_windows_dns_name("example.com"), "example.com");
        assert_eq!(
            decode_windows_dns_name("(3)www(7)example(3)com(0)"),
            "www.example.com"
        );
    }

    #[test]
    fn parse_dns_log_mixes_formats_and_skips_junk() {
        let body = concat!(
            "# a comment\n",
            "01-Jun-2024 12:00:00.000 client @0x1 10.0.0.1#50000 (a.test): query: a.test IN A +\n",
            "6/1/2024 12:00:00 PM 0A00 PACKET 0x00 UDP Rcv 10.0.0.2 80 R Q [0001 D NOERROR] AAAA (1)b(4)test(0)\n",
            "nonsense line\n",
        );
        let records = parse_dns_log(body);
        assert_eq!(records.len(), 2);
        assert!(records
            .iter()
            .any(|q| q.log_format == DnsLogFormat::Bind && q.query_name == "a.test"));
        assert!(records
            .iter()
            .any(|q| q.log_format == DnsLogFormat::WindowsDns && q.query_name == "b.test"));
    }

    #[test]
    fn parse_snort_fast_alert() {
        let line = "06/01-12:00:00.000000  [**] [1:2001:1] ET SCAN Nmap Scripting Engine User-Agent Detected [**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 10.0.0.5:54321 -> 93.184.216.34:443";
        let a = parse_snort_fast_line(line).expect("snort parses");
        assert_eq!(
            a.signature,
            "ET SCAN Nmap Scripting Engine User-Agent Detected"
        );
        assert_eq!(a.rule_id.as_deref(), Some("1:2001:1"));
        assert_eq!(a.priority, Some(2));
        assert_eq!(
            a.classification.as_deref(),
            Some("Attempted Information Leak")
        );
        assert_eq!(a.protocol.as_deref(), Some("TCP"));
        assert_eq!(a.src_ip.as_deref(), Some("10.0.0.5"));
        assert_eq!(a.src_port, Some(54321));
        assert_eq!(a.dst_ip.as_deref(), Some("93.184.216.34"));
        assert_eq!(a.dst_port, Some(443));
        assert_eq!(a.format, IdsAlertFormat::SnortFast);
    }

    #[test]
    fn parse_suricata_eve_alert_line() {
        let line = r#"{"timestamp":"2024-06-01T12:00:00.000000+0000","event_type":"alert","src_ip":"10.0.0.5","src_port":443,"dest_ip":"93.184.216.34","dest_port":54321,"proto":"TCP","alert":{"signature":"ET EXPLOIT CVE-2024-1234","category":"Exploit","severity":1,"gid":1,"signature_id":2002,"rev":3}}"#;
        let a = parse_suricata_eve_line(line).expect("eve parses");
        assert_eq!(a.signature, "ET EXPLOIT CVE-2024-1234");
        assert_eq!(a.classification.as_deref(), Some("Exploit"));
        assert_eq!(a.priority, Some(1));
        assert_eq!(a.rule_id.as_deref(), Some("1:2002:3"));
        assert_eq!(a.protocol.as_deref(), Some("TCP"));
        assert_eq!(a.src_ip.as_deref(), Some("10.0.0.5"));
        assert_eq!(a.format, IdsAlertFormat::SuricataEve);
    }

    #[test]
    fn parse_ids_log_mixes_snort_and_eve() {
        let body = concat!(
            "# comment\n",
            "06/01-12:00:00.000000  [**] [1:1000:1] ET SCAN test [**] [Classification: Scan] [Priority: 3] {UDP} 1.1.1.1:53 -> 2.2.2.2:55000\n",
            r#"{"event_type":"alert","timestamp":"2024-06-01T12:00:00Z","alert":{"signature":"X","category":"Scan","severity":3,"gid":1,"signature_id":999,"rev":1}}"#,
            "\n",
        );
        let records = parse_ids_log(body);
        assert_eq!(records.len(), 2);
        assert!(records
            .iter()
            .any(|a| a.format == IdsAlertFormat::SnortFast));
        assert!(records
            .iter()
            .any(|a| a.format == IdsAlertFormat::SuricataEve));
    }

    #[test]
    fn mitre_routing_by_classification() {
        assert_eq!(mitre_for_ids(Some("ET SCAN Nmap")), "T1595");
        assert_eq!(mitre_for_ids(Some("Trojan C2")), "T1071");
        assert_eq!(mitre_for_ids(Some("Exploit CVE")), "T1190");
        assert_eq!(mitre_for_ids(None), "T1071");
    }

    #[test]
    fn classify_file_recognises_common_filenames() {
        assert_eq!(
            classify_file(Path::new("/var/log/eve.json")),
            Some(DnsOrIds::IdsEve)
        );
        assert_eq!(
            classify_file(Path::new("/var/log/snort/alert.fast")),
            Some(DnsOrIds::IdsSnortFast)
        );
        assert_eq!(
            classify_file(Path::new("/var/log/named.log")),
            Some(DnsOrIds::DnsBind)
        );
        assert!(classify_file(Path::new("/tmp/random.txt")).is_none());
    }
}
