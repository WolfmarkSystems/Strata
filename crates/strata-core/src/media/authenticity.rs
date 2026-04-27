//! Media-authenticity screening (UX-4).
//!
//! Metadata + statistical screening only — NOT an AI detector. The
//! module provides defensible anomaly evidence for the examiner, not a
//! definitive manipulation verdict.
//!
//! MITRE: T1027 (obfuscated files), T1565 (data manipulation).
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

const SUSPICIOUS_SOFTWARE_FRAGMENTS: &[&str] = &[
    "photoshop",
    "gimp",
    "lightroom",
    "capture one",
    "stable diffusion",
    "midjourney",
    "dall-e",
    "dalle",
    "comfyui",
    "python",
    "pillow",
    "imagemagick",
    "sora",
    "runway",
];

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AuthenticityReport {
    pub path: String,
    pub file_type: String,
    pub timestamp_consistent: bool,
    pub timestamp_anomalies: Vec<String>,
    pub software_field: Option<String>,
    pub software_suspicious: bool,
    pub gps_plausible: Option<bool>,
    pub gps_anomalies: Vec<String>,
    pub thumbnail_mismatch: bool,
    pub ela_std_dev: Option<f64>,
    pub ela_flagged: bool,
    pub authenticity_confidence: String,
    pub anomalies: Vec<String>,
}

/// Context gathered from parsers upstream — we don't do EXIF here.
#[derive(Debug, Clone, Default)]
pub struct MediaFacts {
    pub path: String,
    pub file_type: String,
    pub exif_date_original: Option<DateTime<Utc>>,
    pub exif_date_digitized: Option<DateTime<Utc>>,
    pub exif_date_modified: Option<DateTime<Utc>>,
    pub filesystem_created: Option<DateTime<Utc>>,
    pub filesystem_modified: Option<DateTime<Utc>>,
    pub software: Option<String>,
    pub gps_latitude: Option<f64>,
    pub gps_longitude: Option<f64>,
    pub gps_altitude: Option<f64>,
    pub gps_speed_kph: Option<f64>,
    pub gps_timestamp: Option<DateTime<Utc>>,
    pub thumbnail_width: Option<u32>,
    pub thumbnail_height: Option<u32>,
    pub image_width: Option<u32>,
    pub image_height: Option<u32>,
    pub ela_std_dev: Option<f64>,
    pub video_duration_secs: Option<f64>,
}

pub fn analyse(facts: &MediaFacts) -> AuthenticityReport {
    let mut report = AuthenticityReport {
        path: facts.path.clone(),
        file_type: facts.file_type.clone(),
        timestamp_consistent: true,
        ..Default::default()
    };
    // Timestamp checks.
    if let (Some(orig), Some(fs_created)) = (facts.exif_date_original, facts.filesystem_created) {
        if orig.timestamp() > fs_created.timestamp() {
            report.timestamp_consistent = false;
            report
                .timestamp_anomalies
                .push("EXIF DateTimeOriginal is after filesystem created time".into());
        }
    }
    if let (Some(orig), Some(digi)) = (facts.exif_date_original, facts.exif_date_digitized) {
        if (orig.timestamp() - digi.timestamp()).abs() > 60 {
            report.timestamp_consistent = false;
            report.timestamp_anomalies.push(
                "DateTimeOriginal and DateTimeDigitized differ by more than 60 seconds".into(),
            );
        }
    }
    if let (Some(orig), Some(digi), Some(mod_time)) = (
        facts.exif_date_original,
        facts.exif_date_digitized,
        facts.exif_date_modified,
    ) {
        if orig == digi && digi == mod_time {
            // Same-second match on all three is suspicious when the
            // minute/second fields are zero (round-number time).
            let n = orig.naive_utc();
            if n.format("%M:%S").to_string() == "00:00" {
                report.timestamp_consistent = false;
                report.timestamp_anomalies.push(
                    "All EXIF timestamps identical and round-numbered — likely programmatic".into(),
                );
            }
        }
    }
    if let (Some(exif_mod), Some(fs_mod)) = (facts.exif_date_modified, facts.filesystem_modified) {
        if (exif_mod.timestamp() - fs_mod.timestamp()).abs() > 300 {
            report.timestamp_consistent = false;
            report.timestamp_anomalies.push(
                "Filesystem modified time differs from EXIF DateTime by more than 5 minutes".into(),
            );
        }
    }
    // Software field.
    if let Some(software) = &facts.software {
        let lc = software.to_ascii_lowercase();
        if SUSPICIOUS_SOFTWARE_FRAGMENTS.iter().any(|f| lc.contains(f)) {
            report.software_suspicious = true;
            report
                .anomalies
                .push(format!("Software field suggests editing/AI: {}", software));
        }
        report.software_field = Some(software.clone());
    }
    // GPS plausibility.
    if facts.gps_latitude.is_some() || facts.gps_longitude.is_some() {
        let mut ok = true;
        if let Some(lat) = facts.gps_latitude {
            if !(-90.0..=90.0).contains(&lat) {
                ok = false;
                report
                    .gps_anomalies
                    .push(format!("Invalid latitude: {}", lat));
            }
        }
        if let Some(lon) = facts.gps_longitude {
            if !(-180.0..=180.0).contains(&lon) {
                ok = false;
                report
                    .gps_anomalies
                    .push(format!("Invalid longitude: {}", lon));
            }
        }
        if let Some(alt) = facts.gps_altitude {
            if !(-500.0..=9000.0).contains(&alt) {
                ok = false;
                report
                    .gps_anomalies
                    .push(format!("Implausible altitude: {} m", alt));
            }
        }
        if let Some(spd) = facts.gps_speed_kph {
            if spd > 400.0 {
                ok = false;
                report
                    .gps_anomalies
                    .push(format!("Implausible ground speed: {} km/h", spd));
            }
        }
        if let (Some(exif_t), Some(gps_t)) = (facts.exif_date_original, facts.gps_timestamp) {
            if (exif_t.timestamp() - gps_t.timestamp()).abs() > 1800 {
                ok = false;
                report
                    .gps_anomalies
                    .push("GPS timestamp differs from EXIF timestamp by > 30 minutes".into());
            }
        }
        report.gps_plausible = Some(ok);
        for a in &report.gps_anomalies {
            report.anomalies.push(a.clone());
        }
    }
    // Thumbnail mismatch.
    if let (Some(tw), Some(th), Some(iw), Some(ih)) = (
        facts.thumbnail_width,
        facts.thumbnail_height,
        facts.image_width,
        facts.image_height,
    ) {
        if tw > 0 && th > 0 && iw > 0 && ih > 0 {
            let t_ratio = tw as f64 / th as f64;
            let i_ratio = iw as f64 / ih as f64;
            if (t_ratio - i_ratio).abs() > 0.05 {
                report.thumbnail_mismatch = true;
                report.anomalies.push(
                    "Embedded thumbnail aspect ratio differs from main image — possible crop/replace".into(),
                );
            }
        }
    }
    // ELA.
    if let Some(std) = facts.ela_std_dev {
        report.ela_std_dev = Some(std);
        if std > 15.0 {
            report.ela_flagged = true;
            report.anomalies.push(format!(
                "Error Level Analysis std_dev {:.2} exceeds threshold — possible editing (screening indicator, not proof)",
                std
            ));
        }
    }
    // Video-specific: suspiciously short duration.
    if let Some(d) = facts.video_duration_secs {
        if d < 1.0 {
            report.anomalies.push(format!(
                "Video duration {:.2}s is extremely short — common in deepfake clips",
                d
            ));
        }
    }
    // Roll up timestamp anomalies into the full anomaly list.
    for a in &report.timestamp_anomalies {
        if !report.anomalies.contains(a) {
            report.anomalies.push(a.clone());
        }
    }
    // Confidence bucket.
    let count = report.anomalies.len();
    report.authenticity_confidence = match count {
        0 => "High".to_string(),
        1..=2 => "Medium".to_string(),
        _ => "Low".to_string(),
    };
    report
}

/// Simplified Error Level Analysis helper. Given raw pixel bytes of
/// the decoded image and a re-encoded copy, returns standard deviation
/// of per-byte absolute differences.
pub fn ela_std_dev(original: &[u8], recompressed: &[u8]) -> Option<f64> {
    let n = original.len().min(recompressed.len());
    if n == 0 {
        return None;
    }
    let mut sum: f64 = 0.0;
    for i in 0..n {
        sum += (original[i] as i32 - recompressed[i] as i32).abs() as f64;
    }
    let mean = sum / n as f64;
    let mut var: f64 = 0.0;
    for i in 0..n {
        let d = (original[i] as i32 - recompressed[i] as i32).abs() as f64 - mean;
        var += d * d;
    }
    Some((var / n as f64).sqrt())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(secs, 0).expect("ts")
    }

    #[test]
    fn analyse_clean_image_is_high_confidence() {
        let facts = MediaFacts {
            path: "/x/clean.jpg".into(),
            file_type: "JPEG".into(),
            exif_date_original: Some(ts(1_717_243_200)),
            exif_date_digitized: Some(ts(1_717_243_201)),
            exif_date_modified: Some(ts(1_717_243_210)),
            filesystem_created: Some(ts(1_717_243_215)),
            filesystem_modified: Some(ts(1_717_243_212)),
            software: Some("Apple iOS 17.5.1".into()),
            ..Default::default()
        };
        let r = analyse(&facts);
        assert_eq!(r.authenticity_confidence, "High");
        assert!(r.anomalies.is_empty());
    }

    #[test]
    fn analyse_flags_timestamp_anomaly_and_editor_software() {
        let facts = MediaFacts {
            path: "/x/edited.jpg".into(),
            file_type: "JPEG".into(),
            exif_date_original: Some(ts(2_000_000_000)),
            filesystem_created: Some(ts(1_000_000_000)),
            software: Some("Adobe Photoshop 2024".into()),
            ..Default::default()
        };
        let r = analyse(&facts);
        assert!(r
            .timestamp_anomalies
            .iter()
            .any(|a| a.contains("DateTimeOriginal is after filesystem created")));
        assert!(r.software_suspicious);
        assert!(r.authenticity_confidence == "Medium" || r.authenticity_confidence == "Low");
    }

    #[test]
    fn analyse_flags_gps_implausibility() {
        let facts = MediaFacts {
            path: "/x/gps.jpg".into(),
            file_type: "JPEG".into(),
            gps_latitude: Some(200.0),
            gps_longitude: Some(-122.4194),
            gps_altitude: Some(30000.0),
            gps_speed_kph: Some(900.0),
            ..Default::default()
        };
        let r = analyse(&facts);
        assert_eq!(r.gps_plausible, Some(false));
        assert!(r.gps_anomalies.len() >= 3);
        assert_eq!(r.authenticity_confidence, "Low");
    }

    #[test]
    fn analyse_flags_thumbnail_aspect_mismatch() {
        let facts = MediaFacts {
            path: "/x/crop.jpg".into(),
            file_type: "JPEG".into(),
            thumbnail_width: Some(160),
            thumbnail_height: Some(120),
            image_width: Some(1920),
            image_height: Some(600),
            ..Default::default()
        };
        let r = analyse(&facts);
        assert!(r.thumbnail_mismatch);
    }

    #[test]
    fn analyse_flags_ela_above_threshold() {
        let facts = MediaFacts {
            path: "/x/ela.jpg".into(),
            file_type: "JPEG".into(),
            ela_std_dev: Some(42.0),
            ..Default::default()
        };
        let r = analyse(&facts);
        assert!(r.ela_flagged);
    }

    #[test]
    fn ela_std_dev_handles_identical_and_different_buffers() {
        let a = vec![10u8, 20, 30, 40];
        assert_eq!(ela_std_dev(&a, &a), Some(0.0));
        let b = vec![10u8, 30, 30, 50];
        let std = ela_std_dev(&a, &b).expect("std");
        assert!(std > 0.0);
    }
}
