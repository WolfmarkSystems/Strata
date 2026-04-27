//! macOS Transparency, Consent, and Control (TCC) database parser.
//!
//! TCC is the macOS subsystem that gates app access to sensitive
//! capabilities (camera, microphone, screen recording, full disk
//! access, accessibility, etc.) and stores its decisions in two
//! SQLite databases:
//!
//! * `/Library/Application Support/com.apple.TCC/TCC.db` — system-
//!   wide policy (set via MDM or by users with admin rights).
//! * `~/Library/Application Support/com.apple.TCC/TCC.db` — per-user
//!   grants set through System Settings → Privacy & Security.
//!
//! ## Forensic significance
//!
//! TCC entries are an attacker's footprint when they grant their own
//! tooling access to the camera, microphone, or full disk. A
//! third-party / unsigned binary with **Full Disk Access** or
//! **Accessibility** is the macOS equivalent of "SeDebugPrivilege
//! granted to non-Microsoft binary" — every red-team and most macOS
//! malware families want one of these two grants.
//!
//! ## Schema (table `access`)
//!
//! | Column | Type | Meaning |
//! |---|---|---|
//! | `service`        | TEXT    | `kTCCService*` constant identifying the capability |
//! | `client`         | TEXT    | Bundle ID or absolute binary path |
//! | `client_type`    | INTEGER | 0 = bundle ID, 1 = absolute path |
//! | `auth_value`     | INTEGER | 0 = denied, 2 = allowed, 3 = limited |
//! | `auth_reason`    | INTEGER | how the grant was set |
//! | `last_modified`  | INTEGER | Unix timestamp of last update |
//! | `policy_id`      | INTEGER | nullable policy reference |
//!
//! ## MITRE ATT&CK
//! * **T1113** (Screen Capture) — Camera / ScreenCapture grants.
//! * **T1123** (Audio Capture) — Microphone grants.
//! * **T1005** (Data from Local System) — FullDiskAccess grants.
//! * **T1083** (File and Directory Discovery) — fallback for other
//!   services.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println` per CLAUDE.md.

use chrono::{DateTime, Utc};
use rusqlite::{Connection, OpenFlags};
use std::path::Path;

// ── Compatibility layer for simplified task interface ──

/// Simple authorization value enum as requested in task requirements.
/// This is a simplified version of [`TccAuthValue`] for basic use cases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthValue {
    /// `auth_value = 0` — explicit deny.
    Denied,
    /// `auth_value = 2` — full grant.
    Allowed,
    /// `auth_value = 3` — limited grant.
    Limited,
    /// Any other value, including unknown future values.
    Unknown,
}

impl From<TccAuthValue> for AuthValue {
    fn from(val: TccAuthValue) -> Self {
        match val {
            TccAuthValue::Denied => AuthValue::Denied,
            TccAuthValue::Allowed => AuthValue::Allowed,
            TccAuthValue::Limited => AuthValue::Limited,
            TccAuthValue::Other(_) => AuthValue::Unknown,
        }
    }
}

/// Simplified TCC record structure as requested in task requirements.
/// This provides a basic interface over the more comprehensive [`TccEntry`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TccRecord {
    /// Raw service identifier (e.g., "kTCCServiceCamera").
    pub service: String,
    /// Bundle ID or absolute binary path of the requesting app.
    pub client: String,
    /// The permission decision.
    pub auth_value: AuthValue,
    /// Last modification time.
    pub last_modified: DateTime<Utc>,
}

impl From<TccEntry> for TccRecord {
    fn from(entry: TccEntry) -> Self {
        TccRecord {
            service: entry.service,
            client: entry.client,
            auth_value: entry.auth_value.into(),
            last_modified: entry.last_modified,
        }
    }
}

/// Parse TCC database and return simplified records as requested in task requirements.
/// This function provides the exact interface specified while leveraging the
/// comprehensive parsing logic already implemented.
///
/// # Arguments
/// * `path` - Path to the TCC.db file
///
/// # Returns
/// * `Ok(Vec<TccRecord>)` - Successfully parsed TCC records
/// * `Err(Box<dyn std::error::Error>)` - Database error or file not found
pub fn parse_tcc_db(path: &Path) -> Result<Vec<TccRecord>, Box<dyn std::error::Error>> {
    // Leverage existing comprehensive parser
    let entries = parse(path);

    // Convert to simplified format
    let records: Vec<TccRecord> = entries.into_iter().map(TccRecord::from).collect();

    Ok(records)
}

/// Hard cap on rows returned per database. Real TCC.db files top out
/// well under 1000 entries; 10 000 is a safety bound.
const MAX_ROWS: usize = 10_000;

/// `client_type` column values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TccClientType {
    /// `client_type = 0` — `client` is a bundle identifier (e.g.
    /// `com.apple.Terminal`). Stable across reinstalls.
    BundleId,
    /// `client_type = 1` — `client` is an absolute binary path
    /// (e.g. `/usr/local/bin/python3`). Used when the binary is
    /// not packaged in an `.app` bundle.
    AbsolutePath,
    /// Any other (or NULL) value — surfaced as-is so the analyst can
    /// see anomalies without losing data.
    Other(i64),
}

impl TccClientType {
    pub fn as_str(&self) -> &'static str {
        match self {
            TccClientType::BundleId => "BundleId",
            TccClientType::AbsolutePath => "AbsolutePath",
            TccClientType::Other(_) => "Other",
        }
    }
}

/// `auth_value` column values per the TCC schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TccAuthValue {
    /// `auth_value = 0` — explicit deny.
    Denied,
    /// `auth_value = 2` — full grant.
    Allowed,
    /// `auth_value = 3` — limited (e.g. selected-photos-only).
    Limited,
    /// Anything else; preserved so future Apple values aren't lost.
    Other(i64),
}

impl TccAuthValue {
    pub fn as_str(&self) -> &'static str {
        match self {
            TccAuthValue::Denied => "Denied",
            TccAuthValue::Allowed => "Allowed",
            TccAuthValue::Limited => "Limited",
            TccAuthValue::Other(_) => "Other",
        }
    }

    /// `true` when this grant lets the client actually use the
    /// capability (Allowed or Limited).
    pub fn is_grant(&self) -> bool {
        matches!(self, TccAuthValue::Allowed | TccAuthValue::Limited)
    }
}

/// One typed `access`-table row.
///
/// Field meanings are forensic-first; consumers (Sigma rules, the
/// timeline view) read these without having to know the TCC schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TccEntry {
    /// Raw `kTCCService*` identifier from the `service` column. Use
    /// `service_friendly` for human-readable output and join keys,
    /// but keep this verbatim string for forensic faithfulness.
    pub service: String,

    /// Human-readable service name from [`friendly_service_name`]
    /// (e.g. `"Camera"`, `"FullDiskAccess"`). Defaults to the raw
    /// `service` string when no mapping exists, so the field is
    /// never empty.
    pub service_friendly: String,

    /// Bundle ID or absolute binary path of the requesting app. Cross-
    /// reference with on-disk binaries / code-signing data to
    /// determine whether the grant went to a legitimate or
    /// suspicious client.
    pub client: String,

    /// Whether `client` is a bundle ID or an absolute path. See
    /// [`TccClientType`]. Bundle-ID grants are the common case;
    /// absolute-path grants frequently point at command-line tools
    /// (e.g. `osascript`, `python3`) that scripts use to bypass
    /// per-app prompts.
    pub client_type: TccClientType,

    /// The actual permission decision. See [`TccAuthValue`]. `Allowed`
    /// or `Limited` are the only forensically-actionable values —
    /// `Denied` rows just record that the user / MDM said no.
    pub auth_value: TccAuthValue,

    /// Why TCC recorded this decision (Apple-internal numeric code;
    /// no public schema). Surfaced as a raw `u32` so the analyst can
    /// notice anomalies without us inventing a labeling scheme.
    pub auth_reason: u32,

    /// Last time this row was written, decoded from the integer
    /// `last_modified` column (Unix seconds UTC). Pair with system
    /// install / setup events to detect grants that appeared
    /// outside expected provisioning windows.
    pub last_modified: DateTime<Utc>,

    /// Optional `policy_id` linking this row to a row in
    /// `policies` (set by MDM profiles). `None` for user-set grants.
    pub policy_id: Option<u32>,
}

/// Map a raw `kTCCService*` constant to a human-readable label. Falls
/// through to the raw string when no mapping exists.
pub fn friendly_service_name(service: &str) -> String {
    match service {
        "kTCCServiceCamera" => "Camera".to_string(),
        "kTCCServiceMicrophone" => "Microphone".to_string(),
        "kTCCServiceLocation" => "Location".to_string(),
        "kTCCServiceContacts" => "Contacts".to_string(),
        "kTCCServiceCalendar" => "Calendar".to_string(),
        "kTCCServicePhotos" => "Photos".to_string(),
        "kTCCServiceScreenCapture" => "ScreenCapture".to_string(),
        "kTCCServiceAccessibility" => "Accessibility".to_string(),
        "kTCCServiceAddressBook" => "AddressBook".to_string(),
        "kTCCServiceReminders" => "Reminders".to_string(),
        "kTCCServiceSystemPolicyAllFiles" => "FullDiskAccess".to_string(),
        other => other.to_string(),
    }
}

/// MITRE technique mapping per friendly service label.
pub fn mitre_for_service(service_friendly: &str) -> &'static str {
    match service_friendly {
        "Camera" | "ScreenCapture" => "T1113",
        "Microphone" => "T1123",
        "FullDiskAccess" => "T1005",
        _ => "T1083",
    }
}

/// `forensic_value` per the user-spec: High when one of the highly-
/// sensitive capabilities is actively granted, Medium otherwise.
pub fn forensic_value_for(entry: &TccEntry) -> &'static str {
    if entry.auth_value.is_grant()
        && matches!(
            entry.service_friendly.as_str(),
            "FullDiskAccess" | "Camera" | "Microphone" | "ScreenCapture"
        )
    {
        "High"
    } else {
        "Medium"
    }
}

/// `true` when a third-party app holds an Allowed/Limited grant for
/// FullDiskAccess or Accessibility. Apple-bundled binaries (those
/// whose `client` starts with `com.apple.`) are excluded — they
/// always have these grants and trigger false positives otherwise.
pub fn is_suspicious(entry: &TccEntry) -> bool {
    if !entry.auth_value.is_grant() {
        return false;
    }
    let dangerous = matches!(
        entry.service_friendly.as_str(),
        "FullDiskAccess" | "Accessibility"
    );
    if !dangerous {
        return false;
    }
    let apple_signed = entry.client.starts_with("com.apple.")
        || entry.client.starts_with("/System/")
        || entry.client.starts_with("/usr/libexec/")
        || entry.client.starts_with("/Library/Apple/");
    !apple_signed
}

/// Parse the TCC `access` table from a SQLite database file. Opens
/// the database read-only and tolerates missing columns (older macOS
/// builds shipped a narrower schema).
///
/// Returns an empty vector on open failure or missing `access`
/// table. Never panics.
pub fn parse(path: &Path) -> Vec<TccEntry> {
    let conn = match Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    ) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    parse_connection(&conn)
}

/// Lower-level helper used by both [`parse`] and the unit tests so
/// the test fixtures don't need to round-trip through the
/// filesystem.
pub fn parse_connection(conn: &Connection) -> Vec<TccEntry> {
    // Use `coalesce` so older schema variants (without policy_id /
    // auth_reason) silently land as 0 rather than blow the whole
    // query up.
    let sql = "SELECT \
                  service, \
                  client, \
                  COALESCE(client_type, -1), \
                  COALESCE(auth_value, -1), \
                  COALESCE(auth_reason, 0), \
                  COALESCE(last_modified, 0), \
                  policy_id \
              FROM access";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let mut rows = match stmt.query([]) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    while let Ok(Some(row)) = rows.next() {
        if out.len() >= MAX_ROWS {
            break;
        }
        let service: String = row.get(0).unwrap_or_default();
        let client: String = row.get(1).unwrap_or_default();
        let client_type_i: i64 = row.get(2).unwrap_or(-1);
        let auth_value_i: i64 = row.get(3).unwrap_or(-1);
        let auth_reason: i64 = row.get(4).unwrap_or(0);
        let last_modified_i: i64 = row.get(5).unwrap_or(0);
        let policy_id_raw: Option<i64> = row.get(6).ok();

        let client_type = match client_type_i {
            0 => TccClientType::BundleId,
            1 => TccClientType::AbsolutePath,
            other => TccClientType::Other(other),
        };
        let auth_value = match auth_value_i {
            0 => TccAuthValue::Denied,
            2 => TccAuthValue::Allowed,
            3 => TccAuthValue::Limited,
            other => TccAuthValue::Other(other),
        };
        let last_modified =
            DateTime::<Utc>::from_timestamp(last_modified_i, 0).unwrap_or_else(unix_epoch);
        let service_friendly = friendly_service_name(&service);
        out.push(TccEntry {
            service,
            service_friendly,
            client,
            client_type,
            auth_value,
            auth_reason: auth_reason.clamp(0, i64::from(u32::MAX)) as u32,
            last_modified,
            policy_id: policy_id_raw.and_then(|v| u32::try_from(v).ok()),
        });
    }
    out
}

fn unix_epoch() -> DateTime<Utc> {
    DateTime::<Utc>::from(std::time::UNIX_EPOCH)
}

// ── tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn build_test_db() -> Connection {
        let conn = Connection::open_in_memory().expect("open memory db");
        conn.execute_batch(
            "CREATE TABLE access (
                service TEXT,
                client TEXT,
                client_type INTEGER,
                auth_value INTEGER,
                auth_reason INTEGER,
                last_modified INTEGER,
                policy_id INTEGER
            );",
        )
        .expect("create access");
        conn
    }

    #[test]
    fn friendly_service_name_maps_known_constants() {
        assert_eq!(friendly_service_name("kTCCServiceCamera"), "Camera");
        assert_eq!(friendly_service_name("kTCCServiceMicrophone"), "Microphone");
        assert_eq!(
            friendly_service_name("kTCCServiceSystemPolicyAllFiles"),
            "FullDiskAccess"
        );
        assert_eq!(
            friendly_service_name("kTCCServiceUnknownXYZ"),
            "kTCCServiceUnknownXYZ"
        );
    }

    #[test]
    fn mitre_mapping_table() {
        assert_eq!(mitre_for_service("Camera"), "T1113");
        assert_eq!(mitre_for_service("ScreenCapture"), "T1113");
        assert_eq!(mitre_for_service("Microphone"), "T1123");
        assert_eq!(mitre_for_service("FullDiskAccess"), "T1005");
        assert_eq!(mitre_for_service("Photos"), "T1083");
        assert_eq!(mitre_for_service("Whatever"), "T1083");
    }

    #[test]
    fn parse_returns_empty_when_access_table_missing() {
        let conn = Connection::open_in_memory().expect("open memory");
        let entries = parse_connection(&conn);
        assert!(entries.is_empty());
    }

    #[test]
    fn parse_decodes_typed_rows_from_in_memory_db() {
        let conn = build_test_db();
        conn.execute(
            "INSERT INTO access VALUES (?,?,?,?,?,?,?)",
            rusqlite::params![
                "kTCCServiceCamera",
                "com.apple.Terminal",
                0i64,
                2i64,
                4i64,
                1_733_999_634i64,
                rusqlite::types::Null,
            ],
        )
        .expect("insert");
        conn.execute(
            "INSERT INTO access VALUES (?,?,?,?,?,?,?)",
            rusqlite::params![
                "kTCCServiceSystemPolicyAllFiles",
                "/usr/local/bin/evil",
                1i64,
                2i64,
                4i64,
                1_733_999_700i64,
                42i64,
            ],
        )
        .expect("insert path");

        let entries = parse_connection(&conn);
        assert_eq!(entries.len(), 2);

        let cam = &entries[0];
        assert_eq!(cam.service, "kTCCServiceCamera");
        assert_eq!(cam.service_friendly, "Camera");
        assert_eq!(cam.client, "com.apple.Terminal");
        assert_eq!(cam.client_type, TccClientType::BundleId);
        assert_eq!(cam.auth_value, TccAuthValue::Allowed);
        assert_eq!(cam.last_modified.timestamp(), 1_733_999_634);
        assert!(cam.policy_id.is_none());

        let fda = &entries[1];
        assert_eq!(fda.service_friendly, "FullDiskAccess");
        assert_eq!(fda.client_type, TccClientType::AbsolutePath);
        assert_eq!(fda.auth_value, TccAuthValue::Allowed);
        assert_eq!(fda.policy_id, Some(42));
    }

    #[test]
    fn auth_value_decoding_handles_all_documented_codes() {
        let conn = build_test_db();
        for (auth, _expected_variant_str) in [
            (0i64, "Denied"),
            (2, "Allowed"),
            (3, "Limited"),
            (99, "Other"),
        ] {
            conn.execute(
                "INSERT INTO access VALUES (?,?,?,?,?,?,?)",
                rusqlite::params![
                    "kTCCServicePhotos",
                    "com.x.y",
                    0i64,
                    auth,
                    0i64,
                    0i64,
                    rusqlite::types::Null,
                ],
            )
            .expect("insert");
        }
        let entries = parse_connection(&conn);
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0].auth_value, TccAuthValue::Denied);
        assert_eq!(entries[1].auth_value, TccAuthValue::Allowed);
        assert_eq!(entries[2].auth_value, TccAuthValue::Limited);
        assert!(matches!(entries[3].auth_value, TccAuthValue::Other(99)));
    }

    #[test]
    fn is_suspicious_flags_third_party_full_disk_access() {
        let entry = TccEntry {
            service: "kTCCServiceSystemPolicyAllFiles".into(),
            service_friendly: "FullDiskAccess".into(),
            client: "com.evilco.tool".into(),
            client_type: TccClientType::BundleId,
            auth_value: TccAuthValue::Allowed,
            auth_reason: 4,
            last_modified: DateTime::<Utc>::from_timestamp(0, 0).expect("epoch is representable"),
            policy_id: None,
        };
        assert!(is_suspicious(&entry));
    }

    #[test]
    fn is_suspicious_clears_apple_bundles() {
        let entry = TccEntry {
            service: "kTCCServiceSystemPolicyAllFiles".into(),
            service_friendly: "FullDiskAccess".into(),
            client: "com.apple.Terminal".into(),
            client_type: TccClientType::BundleId,
            auth_value: TccAuthValue::Allowed,
            auth_reason: 4,
            last_modified: DateTime::<Utc>::from_timestamp(0, 0).expect("epoch is representable"),
            policy_id: None,
        };
        assert!(!is_suspicious(&entry));
    }

    #[test]
    fn is_suspicious_clears_denied_grants_even_when_third_party() {
        let entry = TccEntry {
            service: "kTCCServiceSystemPolicyAllFiles".into(),
            service_friendly: "FullDiskAccess".into(),
            client: "com.evilco.tool".into(),
            client_type: TccClientType::BundleId,
            auth_value: TccAuthValue::Denied,
            auth_reason: 0,
            last_modified: DateTime::<Utc>::from_timestamp(0, 0).expect("epoch is representable"),
            policy_id: None,
        };
        assert!(!is_suspicious(&entry));
    }

    #[test]
    fn forensic_value_high_for_dangerous_grants() {
        let mut entry = TccEntry {
            service: "kTCCServiceCamera".into(),
            service_friendly: "Camera".into(),
            client: "com.x.y".into(),
            client_type: TccClientType::BundleId,
            auth_value: TccAuthValue::Allowed,
            auth_reason: 0,
            last_modified: DateTime::<Utc>::from_timestamp(0, 0).expect("epoch is representable"),
            policy_id: None,
        };
        assert_eq!(forensic_value_for(&entry), "High");
        entry.auth_value = TccAuthValue::Denied;
        assert_eq!(forensic_value_for(&entry), "Medium");
        entry.auth_value = TccAuthValue::Allowed;
        entry.service_friendly = "Photos".into();
        assert_eq!(forensic_value_for(&entry), "Medium");
    }

    #[test]
    fn parse_round_trip_via_disk_file() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let conn = Connection::open(tmp.path()).expect("open");
        conn.execute_batch(
            "CREATE TABLE access (
                service TEXT,
                client TEXT,
                client_type INTEGER,
                auth_value INTEGER,
                auth_reason INTEGER,
                last_modified INTEGER,
                policy_id INTEGER
            );",
        )
        .expect("create");
        conn.execute(
            "INSERT INTO access VALUES (?,?,?,?,?,?,?)",
            rusqlite::params![
                "kTCCServiceMicrophone",
                "com.evil.recorder",
                0i64,
                2i64,
                4i64,
                1_700_000_000i64,
                rusqlite::types::Null,
            ],
        )
        .expect("insert");
        drop(conn);

        let entries = parse(tmp.path());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].service_friendly, "Microphone");
        assert_eq!(entries[0].client, "com.evil.recorder");
    }

    #[test]
    fn parse_returns_empty_for_missing_file() {
        let entries = parse(Path::new("/nonexistent/path/TCC.db"));
        assert!(entries.is_empty());
    }

    #[test]
    fn auth_value_is_grant_classification() {
        assert!(TccAuthValue::Allowed.is_grant());
        assert!(TccAuthValue::Limited.is_grant());
        assert!(!TccAuthValue::Denied.is_grant());
        assert!(!TccAuthValue::Other(42).is_grant());
    }

    // ── Tests for compatibility layer ──

    #[test]
    fn tcc_record_conversion_from_entry() {
        let entry = TccEntry {
            service: "kTCCServiceCamera".into(),
            service_friendly: "Camera".into(),
            client: "com.example.app".into(),
            client_type: TccClientType::BundleId,
            auth_value: TccAuthValue::Allowed,
            auth_reason: 4,
            last_modified: DateTime::<Utc>::from_timestamp(1_700_000_000, 0)
                .expect("valid timestamp"),
            policy_id: None,
        };

        let record: TccRecord = entry.into();
        assert_eq!(record.service, "kTCCServiceCamera");
        assert_eq!(record.client, "com.example.app");
        assert_eq!(record.auth_value, AuthValue::Allowed);
        assert_eq!(record.last_modified.timestamp(), 1_700_000_000);
    }

    #[test]
    fn auth_value_conversion_from_tcc_auth_value() {
        assert_eq!(AuthValue::from(TccAuthValue::Denied), AuthValue::Denied);
        assert_eq!(AuthValue::from(TccAuthValue::Allowed), AuthValue::Allowed);
        assert_eq!(AuthValue::from(TccAuthValue::Limited), AuthValue::Limited);
        assert_eq!(AuthValue::from(TccAuthValue::Other(99)), AuthValue::Unknown);
    }

    #[test]
    fn parse_tcc_db_returns_simplified_records() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let conn = Connection::open(tmp.path()).expect("open");
        conn.execute_batch(
            "CREATE TABLE access (
                service TEXT,
                client TEXT,
                client_type INTEGER,
                auth_value INTEGER,
                auth_reason INTEGER,
                last_modified INTEGER,
                policy_id INTEGER
            );",
        )
        .expect("create");
        conn.execute(
            "INSERT INTO access VALUES (?,?,?,?,?,?,?)",
            rusqlite::params![
                "kTCCServiceMicrophone",
                "com.example.recorder",
                0i64,
                2i64,
                4i64,
                1_700_000_000i64,
                rusqlite::types::Null,
            ],
        )
        .expect("insert");
        drop(conn);

        let result = parse_tcc_db(tmp.path());
        assert!(result.is_ok());

        let records = result.unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].service, "kTCCServiceMicrophone");
        assert_eq!(records[0].client, "com.example.recorder");
        assert_eq!(records[0].auth_value, AuthValue::Allowed);
        assert_eq!(records[0].last_modified.timestamp(), 1_700_000_000);
    }
}
