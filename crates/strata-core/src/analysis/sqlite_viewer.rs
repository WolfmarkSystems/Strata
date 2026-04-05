use crate::errors::ForensicError;
use time::{Duration, OffsetDateTime};

pub struct HeuristicSqliteViewer;

impl Default for HeuristicSqliteViewer {
    fn default() -> Self {
        Self::new()
    }
}

impl HeuristicSqliteViewer {
    pub fn new() -> Self {
        Self
    }

    /// Intercepts raw SQLite generic INTEGER or REAL values from `.db` files and uses magnitude analysis
    /// to intelligently identify if it represents Mac Absolute, Unix, Windows FileTime, WebKit, or standard Javascript epochs.
    pub fn auto_convert_time(&self, raw_value: i64) -> Result<String, ForensicError> {
        let converted_time = match raw_value {
            // Mac Absolute Time (Apple CoreData): Seconds since Jan 1, 2001
            // e.g. 700000000 is ~2023
            val if (500_000_000..=1_000_000_000).contains(&val) => {
                let mac_epoch = OffsetDateTime::from_unix_timestamp(978307200).unwrap();
                mac_epoch
                    .checked_add(Duration::seconds(val))
                    .map(|d| format!("{} UTC (Mac Absolute)", d))
            }

            // Unix Seconds: Seconds since Jan 1, 1970
            // e.g. 1700000000 is ~2023
            val if (1_000_000_000..=2_500_000_000).contains(&val) => {
                OffsetDateTime::from_unix_timestamp(val)
                    .ok()
                    .map(|d| format!("{} UTC (Unix Epoch)", d))
            }

            // Unix Milliseconds (JavaScript / Java): Milliseconds since Jan 1, 1970
            // e.g. 1700000000000
            val if (1_000_000_000_000..=2_500_000_000_000).contains(&val) => {
                OffsetDateTime::from_unix_timestamp(val / 1000)
                    .ok()
                    .map(|d| format!("{} UTC (Unix Ms)", d))
            }

            // WebKit / Chrome Time: Microseconds since Jan 1, 1601
            // Windows FileTime: 100-Nanosecond intervals since Jan 1, 1601
            // Magnitudes for both are massive. FileTime is ~130000000000000000
            val if val > 10_000_000_000_000_000 => {
                // FileTime calculation (ticks to seconds, minus offset to 1970)
                let seconds = (val / 10_000_000) - 11644473600;
                OffsetDateTime::from_unix_timestamp(seconds)
                    .ok()
                    .map(|d| format!("{} UTC (Windows FileTime)", d))
            }

            // Fallback for WebKit format (if it falls between the two massive integers)
            val if val > 1_000_000_000_000_000 && val < 10_000_000_000_000_000 => {
                let seconds = (val / 1_000_000) - 11644473600;
                OffsetDateTime::from_unix_timestamp(seconds)
                    .ok()
                    .map(|d| format!("{} UTC (WebKit/Chrome Time)", d))
            }

            _ => None,
        };

        match converted_time {
            Some(t) => Ok(t),
            None => Err(ForensicError::MalformedData(String::from(
                "Value does not immediately map to a known forensic epoch.",
            ))),
        }
    }
}
