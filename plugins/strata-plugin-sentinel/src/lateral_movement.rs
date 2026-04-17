//! Lateral-movement correlation (R-3).
//!
//! Research reference: masstin (MIT) — studied only; implementation
//! written independently.
//!
//! Consumes a time-ordered stream of authentication-related Windows
//! Event Log records and emits a higher-level "Lateral Movement"
//! timeline entry when two or more correlated events line up within a
//! 60-second window.
//!
//! ## Correlated event IDs
//! * **4624 logon_type=3** — inbound network logon (SMB / WMI / PS
//!   remoting).
//! * **4624 logon_type=10** — RemoteInteractive (RDP inbound).
//! * **4648** — explicit credential logon (pass-the-hash / PTT).
//! * **4768 / 4769** — Kerberos TGT / service ticket requests.
//! * **4776** — NTLM authentication (cross-domain).
//! * **5140 / 5145** — network-share object access (SMB).
//! * **7045** — service install on remote system.
//!
//! ## Confidence
//! * **High**: two or more correlated events within the correlation
//!   window (default 60 s) sharing the same target account.
//! * **Medium**: a single 4648 or 4624 type 10 record in isolation.
//! * **Low**: any other single-event signal we still surface.
//!
//! ## MITRE ATT&CK
//! * **T1021.001** — Remote Services: RDP.
//! * **T1021.002** — Remote Services: SMB / Windows Admin Shares.
//! * **T1550.002** — Use Alternate Authentication Material: PtH.
//! * **T1558** — Steal or Forge Kerberos Tickets.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Duration, Utc};

/// Default correlation window in seconds.
pub const DEFAULT_WINDOW_SECS: i64 = 60;

/// A single interesting event ingested from the EVTX pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventRecord {
    /// Event ID (4624, 4648, …).
    pub event_id: u32,
    /// Event time in UTC.
    pub timestamp: DateTime<Utc>,
    /// For logon events, the target account.
    pub target_account: Option<String>,
    /// For logon events, source IP or workstation.
    pub source_ip: Option<String>,
    /// For 4624, the LogonType field (3 = network, 10 = RDP).
    pub logon_type: Option<i64>,
}

/// Kind of lateral movement surfaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LateralMovementKind {
    Rdp,
    Smb,
    Kerberos,
    Ntlm,
    Service,
    PassTheHash,
}

impl LateralMovementKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            LateralMovementKind::Rdp => "RDP",
            LateralMovementKind::Smb => "SMB",
            LateralMovementKind::Kerberos => "Kerberos",
            LateralMovementKind::Ntlm => "NTLM",
            LateralMovementKind::Service => "Service",
            LateralMovementKind::PassTheHash => "PassTheHash",
        }
    }

    pub fn mitre(&self) -> &'static str {
        match self {
            LateralMovementKind::Rdp => "T1021.001",
            LateralMovementKind::Smb | LateralMovementKind::Service => "T1021.002",
            LateralMovementKind::PassTheHash | LateralMovementKind::Ntlm => "T1550.002",
            LateralMovementKind::Kerberos => "T1558",
        }
    }
}

/// Confidence tier for a surfaced indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl Confidence {
    pub fn as_str(&self) -> &'static str {
        match self {
            Confidence::High => "High",
            Confidence::Medium => "Medium",
            Confidence::Low => "Low",
        }
    }
}

/// One detected lateral-movement indicator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LateralMovement {
    pub kind: LateralMovementKind,
    pub source_ip: Option<String>,
    pub target_account: String,
    pub timestamp: DateTime<Utc>,
    /// Pipe-separated event IDs involved (`"4648|4624"`).
    pub correlated_events: String,
    pub confidence: Confidence,
}

/// Correlator — stateful across a batch of events.
pub struct LateralMovementDetector {
    window: Duration,
}

impl Default for LateralMovementDetector {
    fn default() -> Self {
        Self::new(DEFAULT_WINDOW_SECS)
    }
}

impl LateralMovementDetector {
    pub fn new(window_secs: i64) -> Self {
        Self {
            window: Duration::seconds(window_secs.max(1)),
        }
    }

    /// Ingest an already-time-sorted slice of events and return every
    /// correlated indicator. Stable order: each emitted indicator is
    /// placed at the timestamp of its latest contributing event.
    pub fn detect(&self, events: &[EventRecord]) -> Vec<LateralMovement> {
        let mut out = Vec::new();
        // Group by (target_account) — correlations require a shared
        // account. Events lacking target_account are evaluated as
        // standalone.
        for (i, ev) in events.iter().enumerate() {
            let Some(account) = ev.target_account.as_deref() else {
                if let Some(single) = single_event_indicator(ev) {
                    out.push(single);
                }
                continue;
            };
            // Look for an earlier event within the window for the same
            // account that, combined with this one, signals a high-
            // confidence correlation.
            let earliest = ev.timestamp - self.window;
            let mut correlated_ids: Vec<u32> = Vec::new();
            let mut kind: Option<LateralMovementKind> = None;
            let mut source_ip = ev.source_ip.clone();
            for prior in events[..i].iter().rev() {
                if prior.timestamp < earliest {
                    break;
                }
                if prior.target_account.as_deref() != Some(account) {
                    continue;
                }
                if let Some(k) = correlate_pair(prior, ev) {
                    correlated_ids.push(prior.event_id);
                    correlated_ids.push(ev.event_id);
                    kind = Some(k);
                    if source_ip.is_none() {
                        source_ip = prior.source_ip.clone();
                    }
                    break;
                }
            }
            if let Some(kind) = kind {
                correlated_ids.sort_unstable();
                correlated_ids.dedup();
                let correlated_events = correlated_ids
                    .iter()
                    .map(|id| id.to_string())
                    .collect::<Vec<_>>()
                    .join("|");
                out.push(LateralMovement {
                    kind,
                    source_ip,
                    target_account: account.to_string(),
                    timestamp: ev.timestamp,
                    correlated_events,
                    confidence: Confidence::High,
                });
                continue;
            }
            if let Some(single) = single_event_indicator(ev) {
                out.push(single);
            }
        }
        out
    }
}

fn single_event_indicator(ev: &EventRecord) -> Option<LateralMovement> {
    let target = ev.target_account.clone().unwrap_or_default();
    match ev.event_id {
        4648 => Some(LateralMovement {
            kind: LateralMovementKind::PassTheHash,
            source_ip: ev.source_ip.clone(),
            target_account: target,
            timestamp: ev.timestamp,
            correlated_events: "4648".to_string(),
            confidence: Confidence::Medium,
        }),
        4624 if ev.logon_type == Some(10) => Some(LateralMovement {
            kind: LateralMovementKind::Rdp,
            source_ip: ev.source_ip.clone(),
            target_account: target,
            timestamp: ev.timestamp,
            correlated_events: "4624".to_string(),
            confidence: Confidence::Medium,
        }),
        4624 if ev.logon_type == Some(3) => Some(LateralMovement {
            kind: LateralMovementKind::Smb,
            source_ip: ev.source_ip.clone(),
            target_account: target,
            timestamp: ev.timestamp,
            correlated_events: "4624".to_string(),
            confidence: Confidence::Low,
        }),
        4768 | 4769 => Some(LateralMovement {
            kind: LateralMovementKind::Kerberos,
            source_ip: ev.source_ip.clone(),
            target_account: target,
            timestamp: ev.timestamp,
            correlated_events: ev.event_id.to_string(),
            confidence: Confidence::Low,
        }),
        4776 => Some(LateralMovement {
            kind: LateralMovementKind::Ntlm,
            source_ip: ev.source_ip.clone(),
            target_account: target,
            timestamp: ev.timestamp,
            correlated_events: "4776".to_string(),
            confidence: Confidence::Low,
        }),
        5140 | 5145 => Some(LateralMovement {
            kind: LateralMovementKind::Smb,
            source_ip: ev.source_ip.clone(),
            target_account: target,
            timestamp: ev.timestamp,
            correlated_events: ev.event_id.to_string(),
            confidence: Confidence::Low,
        }),
        7045 => Some(LateralMovement {
            kind: LateralMovementKind::Service,
            source_ip: ev.source_ip.clone(),
            target_account: target,
            timestamp: ev.timestamp,
            correlated_events: "7045".to_string(),
            confidence: Confidence::Medium,
        }),
        _ => None,
    }
}

/// Decide whether two time-adjacent events co-sign a higher-confidence
/// indicator. Conservative: only the combinations that DFIR practice
/// treats as lateral-movement confirmations.
fn correlate_pair(a: &EventRecord, b: &EventRecord) -> Option<LateralMovementKind> {
    let (first_id, first_lt, second_id, second_lt) =
        (a.event_id, a.logon_type, b.event_id, b.logon_type);
    // 4624 type 10 + 4648 — RDP with explicit creds (more specific,
    // checked before the generic 4648+4624 pair).
    if (first_id == 4624 && first_lt == Some(10) && second_id == 4648)
        || (first_id == 4648 && second_id == 4624 && second_lt == Some(10))
    {
        return Some(LateralMovementKind::Rdp);
    }
    // 4648 + 4624 (any logon_type) — explicit-cred then successful logon.
    if (first_id == 4648 && second_id == 4624) || (first_id == 4624 && second_id == 4648) {
        return Some(LateralMovementKind::PassTheHash);
    }
    // 4624 type 3 + 5140/5145 — network logon + share access = SMB lateral.
    let is_share_access = |id: u32| matches!(id, 5140 | 5145);
    if (first_id == 4624 && first_lt == Some(3) && is_share_access(second_id))
        || (is_share_access(first_id) && second_id == 4624 && second_lt == Some(3))
    {
        return Some(LateralMovementKind::Smb);
    }
    // 4624 type 3 + 7045 — network logon + remote service install.
    if (first_id == 4624 && first_lt == Some(3) && second_id == 7045)
        || (first_id == 7045 && second_id == 4624 && second_lt == Some(3))
    {
        return Some(LateralMovementKind::Service);
    }
    // 4768/4769 + 4624 — Kerberos ticket followed by logon.
    let is_krb = |id: u32| matches!(id, 4768 | 4769);
    if (is_krb(first_id) && second_id == 4624) || (first_id == 4624 && is_krb(second_id)) {
        return Some(LateralMovementKind::Kerberos);
    }
    // 4776 + 4624 — NTLM auth + logon.
    if (first_id == 4776 && second_id == 4624) || (first_id == 4624 && second_id == 4776) {
        return Some(LateralMovementKind::Ntlm);
    }
    None
}

// ── tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn evt(event_id: u32, ts: i64, account: &str, lt: Option<i64>, ip: Option<&str>) -> EventRecord {
        EventRecord {
            event_id,
            timestamp: DateTime::<Utc>::from_timestamp(ts, 0)
                .expect("timestamp"),
            target_account: Some(account.to_string()),
            source_ip: ip.map(|s| s.to_string()),
            logon_type: lt,
        }
    }

    #[test]
    fn detect_rdp_via_4648_plus_4624_type_10() {
        let d = LateralMovementDetector::default();
        let events = vec![
            evt(4648, 1_000, "alice", None, Some("10.0.0.9")),
            evt(4624, 1_020, "alice", Some(10), Some("10.0.0.9")),
        ];
        let hits = d.detect(&events);
        let high: Vec<&LateralMovement> =
            hits.iter().filter(|m| m.confidence == Confidence::High).collect();
        assert_eq!(high.len(), 1);
        assert_eq!(high[0].kind, LateralMovementKind::Rdp);
        assert_eq!(high[0].correlated_events, "4624|4648");
        assert_eq!(high[0].target_account, "alice");
    }

    #[test]
    fn detect_smb_via_4624_type_3_plus_share_access() {
        let d = LateralMovementDetector::default();
        let events = vec![
            evt(4624, 2_000, "svc-backup", Some(3), Some("10.0.0.50")),
            evt(5140, 2_010, "svc-backup", None, Some("10.0.0.50")),
        ];
        let hits = d.detect(&events);
        assert!(hits.iter().any(|m| m.kind == LateralMovementKind::Smb
            && m.confidence == Confidence::High));
    }

    #[test]
    fn detect_service_install_correlated_with_network_logon() {
        let d = LateralMovementDetector::default();
        let events = vec![
            evt(4624, 3_000, "admin", Some(3), Some("10.0.0.77")),
            evt(7045, 3_030, "admin", None, Some("10.0.0.77")),
        ];
        let hits = d.detect(&events);
        assert!(hits.iter().any(|m| m.kind == LateralMovementKind::Service
            && m.confidence == Confidence::High));
    }

    #[test]
    fn lone_4648_is_medium_confidence() {
        let d = LateralMovementDetector::default();
        let events = vec![evt(4648, 10_000, "alice", None, Some("10.0.0.1"))];
        let hits = d.detect(&events);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].confidence, Confidence::Medium);
        assert_eq!(hits[0].kind, LateralMovementKind::PassTheHash);
    }

    #[test]
    fn events_outside_window_do_not_correlate() {
        let d = LateralMovementDetector::new(60);
        let events = vec![
            evt(4648, 10_000, "alice", None, Some("10.0.0.1")),
            evt(4624, 10_200, "alice", Some(10), Some("10.0.0.1")),
        ];
        let hits = d.detect(&events);
        // 200 s > 60 s window → no High-confidence correlation; each
        // event is surfaced individually.
        assert!(!hits.iter().any(|m| m.confidence == Confidence::High));
    }

    #[test]
    fn mitre_maps_per_kind() {
        assert_eq!(LateralMovementKind::Rdp.mitre(), "T1021.001");
        assert_eq!(LateralMovementKind::Smb.mitre(), "T1021.002");
        assert_eq!(LateralMovementKind::PassTheHash.mitre(), "T1550.002");
        assert_eq!(LateralMovementKind::Kerberos.mitre(), "T1558");
    }
}
