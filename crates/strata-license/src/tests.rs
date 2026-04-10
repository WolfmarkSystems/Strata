use crate::free_tier::{FREE_FEATURES, PRO_FEATURES, TRIAL_FEATURES};
use crate::generate_machine_id;
use crate::license::{LicenseTier, StrataLicense};
use crate::trial::{TrialState, is_trial_expired, trial_days_remaining};
use crate::validator::LicenseValidator;
// `machine_id_matches` is only exercised by the Windows-only
// `test_machine_id_consistency` test below, so gate the import to avoid
// an unused-import warning on macOS/Linux.
#[cfg(target_os = "windows")]
use crate::machine_id_matches;
use chrono::{Duration, Utc};
use serde_json::Value;

// Windows-only: the machine-ID generator currently relies on a Windows-specific
// hardware identifier source. On macOS/Linux the generator returns Err(..) or a
// different-length value, so these assertions can only be validated on Windows.
#[cfg(target_os = "windows")]
#[test]
fn test_machine_id_generation() {
    let machine_id = generate_machine_id().expect("machine id should generate");
    assert_eq!(machine_id.len(), 64);
    assert!(machine_id.chars().all(|c| c.is_ascii_hexdigit()));
}

#[cfg(target_os = "windows")]
#[test]
fn test_machine_id_consistency() {
    let first = generate_machine_id().expect("first machine id");
    let second = generate_machine_id().expect("second machine id");
    assert_eq!(first, second);
    assert!(machine_id_matches(&first));
}

#[test]
fn test_license_serialization() {
    let license = sample_license();
    let encoded = serde_json::to_string(&license).expect("serialize license");
    let decoded: StrataLicense = serde_json::from_str(&encoded).expect("deserialize license");
    assert_eq!(decoded, license);

    let as_value: Value = serde_json::from_str(&encoded).expect("json value");
    assert_eq!(as_value["product"], "strata-tree");
}

#[test]
fn test_feature_checking() {
    let validator = LicenseValidator::new();
    let license = sample_license();
    assert!(validator.has_feature(&license, "timeline"));
    assert!(!validator.has_feature(&license, "plugins"));
}

#[test]
fn test_trial_expiry_calculation() {
    let state = TrialState {
        machine_id: "abc".to_string(),
        product: "strata-tree".to_string(),
        trial_start: Utc::now() - Duration::days(31),
        trial_days: 30,
    };

    assert_eq!(trial_days_remaining(&state), 0);
    assert!(is_trial_expired(&state));
}

#[test]
fn test_days_remaining_perpetual() {
    let mut license = sample_license();
    license.expires_at = None;
    assert_eq!(LicenseValidator::days_remaining(&license), None);
}

#[test]
fn test_days_remaining_timed() {
    let mut license = sample_license();
    license.expires_at = Some(Utc::now() + Duration::days(15));

    let remaining = LicenseValidator::days_remaining(&license).expect("remaining days");
    assert!(remaining >= 14);
    assert!(remaining <= 15);
}

#[test]
fn test_free_tier_features() {
    assert_eq!(FREE_FEATURES.len(), 2);
    assert!(FREE_FEATURES.contains(&"hex_editor"));
    assert!(FREE_FEATURES.contains(&"report_export"));
    assert!(TRIAL_FEATURES.len() > PRO_FEATURES.len());
}

fn sample_license() -> StrataLicense {
    StrataLicense {
        license_id: "f6f98788-0e94-474e-b7ab-35cb64c6481a".to_string(),
        product: "strata-tree".to_string(),
        tier: LicenseTier::Professional,
        licensee_name: "Examiner".to_string(),
        licensee_org: "Wolfmark Systems".to_string(),
        machine_id: generate_machine_id().unwrap_or_else(|_| "0".repeat(64)),
        issued_at: Utc::now() - Duration::days(1),
        expires_at: Some(Utc::now() + Duration::days(30)),
        features: vec![
            "hex_editor".to_string(),
            "registry_viewer".to_string(),
            "timeline".to_string(),
        ],
        signature: String::new(),
    }
}
