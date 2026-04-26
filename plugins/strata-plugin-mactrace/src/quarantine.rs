//! macOS quarantine xattr parsing and provenance correlation.

use chrono::{DateTime, Utc};

const APPLE_EPOCH_OFFSET: i64 = 978_307_200;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantineXattr {
    pub flags_hex: String,
    pub timestamp_unix: Option<i64>,
    pub agent: Option<String>,
    pub origin_url: Option<String>,
    pub data_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadExecutionCorrelation {
    pub downloaded_path: String,
    pub executed_path: String,
    pub origin_url: Option<String>,
    pub agent: Option<String>,
    pub confidence: &'static str,
}

pub fn parse_quarantine_xattr(data: &[u8]) -> Option<QuarantineXattr> {
    let text = String::from_utf8_lossy(data);
    let line = text.lines().find(|line| line.contains(';'))?.trim();
    let parts: Vec<&str> = line.split(';').collect();
    if parts.len() < 3 {
        return None;
    }
    let flags_hex = parts.first()?.trim().to_string();
    let timestamp_unix = parts
        .get(1)
        .and_then(|raw| i64::from_str_radix(raw.trim(), 16).ok())
        .map(|apple_secs| apple_secs.saturating_add(APPLE_EPOCH_OFFSET));
    let agent = non_empty_part(parts.get(2).copied());
    let origin_url = non_empty_part(parts.get(3).copied());
    let data_url = non_empty_part(parts.get(4).copied());
    Some(QuarantineXattr {
        flags_hex,
        timestamp_unix,
        agent,
        origin_url,
        data_url,
    })
}

pub fn timestamp_utc(q: &QuarantineXattr) -> Option<DateTime<Utc>> {
    DateTime::<Utc>::from_timestamp(q.timestamp_unix?, 0)
}

pub fn correlate_download_execution(
    downloaded_path: &str,
    quarantine: &QuarantineXattr,
    executed_path: &str,
) -> Option<DownloadExecutionCorrelation> {
    if downloaded_path.is_empty() || executed_path.is_empty() {
        return None;
    }
    let downloaded_name = std::path::Path::new(downloaded_path)
        .file_name()
        .and_then(|n| n.to_str())?;
    let executed_name = std::path::Path::new(executed_path)
        .file_name()
        .and_then(|n| n.to_str())?;
    if !downloaded_name.eq_ignore_ascii_case(executed_name) {
        return None;
    }
    let from_downloads = downloaded_path.to_ascii_lowercase().contains("/downloads/");
    Some(DownloadExecutionCorrelation {
        downloaded_path: downloaded_path.to_string(),
        executed_path: executed_path.to_string(),
        origin_url: quarantine
            .data_url
            .clone()
            .or_else(|| quarantine.origin_url.clone()),
        agent: quarantine.agent.clone(),
        confidence: if from_downloads { "high" } else { "medium" },
    })
}

fn non_empty_part(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "(null)")
        .map(ToString::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_quarantine_xattr_fields() {
        let q = parse_quarantine_xattr(
            b"0083;65A1D300;Safari;https://example.test/download;https://cdn.example.test/payload.dmg",
        )
        .expect("quarantine xattr");
        assert_eq!(q.flags_hex, "0083");
        assert_eq!(q.agent.as_deref(), Some("Safari"));
        assert_eq!(
            q.origin_url.as_deref(),
            Some("https://example.test/download")
        );
        assert_eq!(
            q.data_url.as_deref(),
            Some("https://cdn.example.test/payload.dmg")
        );
        assert_eq!(q.timestamp_unix, Some(2_683_411_328));
    }

    #[test]
    fn quarantine_timestamp_converts_to_utc() {
        let q = parse_quarantine_xattr(b"0083;00000001;curl;https://o;https://d")
            .expect("quarantine xattr");
        assert_eq!(
            timestamp_utc(&q).map(|ts| ts.to_rfc3339()),
            Some("2001-01-01T00:00:01+00:00".to_string())
        );
    }

    #[test]
    fn correlates_internet_download_with_execution() {
        let q = parse_quarantine_xattr(
            b"0083;00000001;Safari;https://landing;https://cdn.example/payload.app",
        )
        .expect("quarantine xattr");
        let corr = correlate_download_execution(
            "/Users/ada/Downloads/payload.app",
            &q,
            "/Users/ada/Downloads/payload.app",
        )
        .expect("correlation");
        assert_eq!(corr.confidence, "high");
        assert_eq!(
            corr.origin_url.as_deref(),
            Some("https://cdn.example/payload.app")
        );
    }

    #[test]
    fn refuses_execution_correlation_for_different_file_names() {
        let q = parse_quarantine_xattr(b"0083;00000001;Safari;https://landing;https://cdn/a")
            .expect("quarantine xattr");
        assert!(
            correlate_download_execution("/Users/ada/Downloads/a", &q, "/Applications/b").is_none()
        );
    }
}
