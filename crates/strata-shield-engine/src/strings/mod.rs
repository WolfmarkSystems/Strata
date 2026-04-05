use rusqlite::types::{FromSql, FromSqlError, ValueRef};
use rusqlite::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

pub const EXTRACTOR_VERSION: &str = "1.0.0";

pub const FLAG_TRUNCATED: u32 = 1 << 0;
pub const FLAG_SAMPLED: u32 = 1 << 1;
pub const FLAG_UTF16_PRESENT: u32 = 1 << 2;
pub const FLAG_ASCII_PRESENT: u32 = 1 << 3;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringsExtractOptions {
    pub min_len_ascii: usize,
    pub min_len_utf16: usize,
    pub max_file_size_bytes: u64,
    pub max_output_chars: usize,
    pub sample_bytes: u64,
    pub allow_categories: Vec<String>,
    pub deny_extensions: Vec<String>,
    pub entropy_max: Option<f64>,
    pub max_tokens: usize,
    pub max_sample_strings: usize,
}

impl Default for StringsExtractOptions {
    fn default() -> Self {
        Self {
            min_len_ascii: 6,
            min_len_utf16: 6,
            max_file_size_bytes: 50 * 1024 * 1024,
            max_output_chars: 200_000,
            sample_bytes: 8 * 1024 * 1024,
            allow_categories: vec![
                "Executable".to_string(),
                "Document".to_string(),
                "Archive".to_string(),
                "Script".to_string(),
                "Unknown".to_string(),
            ],
            deny_extensions: vec![
                "jpg".to_string(),
                "jpeg".to_string(),
                "png".to_string(),
                "gif".to_string(),
                "bmp".to_string(),
                "mp4".to_string(),
                "mov".to_string(),
                "avi".to_string(),
                "mkv".to_string(),
                "mp3".to_string(),
                "wav".to_string(),
                "zip".to_string(),
                "rar".to_string(),
                "7z".to_string(),
                "gz".to_string(),
                "tar".to_string(),
            ],
            entropy_max: Some(7.5),
            max_tokens: 1000,
            max_sample_strings: 50,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedStrings {
    pub ascii_count: usize,
    pub utf16_count: usize,
    pub total_chars: usize,
    pub truncated: bool,
    pub sampled: bool,
    pub flags: u32,
    pub strings_text: String,
    pub strings_json: StringsJson,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StringsJson {
    pub ascii_count: usize,
    pub utf16_count: usize,
    pub total_chars: usize,
    pub truncated: bool,
    pub sampled: bool,
    pub tokens_count: usize,
    pub top_tokens: Vec<String>,
    pub url_count: usize,
    pub email_count: usize,
    pub ip_count: usize,
    pub path_count: usize,
    pub base64_count: usize,
    pub url_samples: Vec<String>,
    pub email_samples: Vec<String>,
    pub ip_samples: Vec<String>,
    pub path_samples: Vec<String>,
    pub base64_samples: Vec<String>,
    pub warnings: Vec<String>,
}

impl FromSql for StringsJson {
    fn column_result(value: ValueRef<'_>) -> Result<Self, FromSqlError> {
        let json_str = String::column_result(value)?;
        Ok(serde_json::from_str(&json_str).unwrap_or_default())
    }
}

pub fn should_extract_strings(
    file_path: &str,
    size_bytes: u64,
    category: Option<&str>,
    entropy: Option<f64>,
    opts: &StringsExtractOptions,
) -> bool {
    if size_bytes == 0 {
        return false;
    }

    if size_bytes > opts.max_file_size_bytes {
        if size_bytes <= opts.sample_bytes {
        } else {
            return false;
        }
    }

    if let Some(ext) = Path::new(file_path)
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_lowercase())
    {
        if opts.deny_extensions.contains(&ext) {
            return false;
        }
    }

    if let Some(cat) = category {
        if !opts.allow_categories.contains(&cat.to_string()) {
            return false;
        }
    }

    if let Some(ent) = entropy {
        if let Some(max_ent) = opts.entropy_max {
            if ent > max_ent {
                return false;
            }
        }
    }

    true
}

pub fn extract_strings(data: &[u8], opts: &StringsExtractOptions) -> ExtractedStrings {
    let mut ascii_strings: Vec<String> = Vec::new();
    let mut utf16_strings: Vec<String> = Vec::new();
    let mut current_ascii = String::new();

    let sampled = data.len() as u64 > opts.sample_bytes;
    let mut flags = 0u32;
    if sampled {
        flags |= FLAG_SAMPLED;
    }

    let data_to_process = if sampled {
        let sample_half = (opts.sample_bytes / 2) as usize;
        let len = data.len();
        if len > sample_half * 2 {
            let mut combined = Vec::with_capacity(sample_half * 2);
            combined.extend_from_slice(&data[..sample_half]);
            combined.extend_from_slice(&data[len - sample_half..]);
            combined
        } else {
            data.to_vec()
        }
    } else {
        data.to_vec()
    };

    for &byte in &data_to_process {
        if (0x20..=0x7E).contains(&byte) {
            current_ascii.push(byte as char);
            continue;
        }

        if !current_ascii.is_empty() && current_ascii.len() >= opts.min_len_ascii {
            ascii_strings.push(current_ascii.clone());
        }
        current_ascii.clear();
    }

    if !current_ascii.is_empty() && current_ascii.len() >= opts.min_len_ascii {
        ascii_strings.push(current_ascii);
    }

    // Detect UTF-16LE ASCII-range strings (e.g., H\0e\0l\0l\0o\0).
    let mut i = 0usize;
    let mut current_utf16 = String::new();
    while i + 1 < data_to_process.len() {
        let lo = data_to_process[i];
        let hi = data_to_process[i + 1];
        if (0x20..=0x7E).contains(&lo) && hi == 0 {
            current_utf16.push(lo as char);
            i += 2;
            continue;
        }

        if current_utf16.len() >= opts.min_len_utf16 {
            utf16_strings.push(current_utf16.clone());
        }
        current_utf16.clear();
        i += 1;
    }

    if current_utf16.len() >= opts.min_len_utf16 {
        utf16_strings.push(current_utf16);
    }

    if !ascii_strings.is_empty() {
        flags |= FLAG_ASCII_PRESENT;
    }
    if !utf16_strings.is_empty() {
        flags |= FLAG_UTF16_PRESENT;
    }

    let all_strings: Vec<String> = ascii_strings
        .iter()
        .chain(utf16_strings.iter())
        .cloned()
        .collect();

    let mut tokens: Vec<String> = Vec::new();
    for s in &all_strings {
        for word in s.split_whitespace() {
            if word.len() >= 4 {
                tokens.push(word.to_string());
            }
        }
    }
    tokens.sort();
    tokens.dedup();
    let tokens_count = tokens.len();
    let token_counts: std::collections::HashMap<&str, usize> =
        tokens.iter().fold(HashMap::new(), |mut acc, s| {
            *acc.entry(s.as_str()).or_insert(0) += 1;
            acc
        });
    let mut top_tokens: Vec<(usize, &str)> = token_counts
        .into_iter()
        .filter(|(_, count)| *count >= 1)
        .map(|(k, v)| (v, k))
        .collect();
    top_tokens.sort_by(|a, b| b.0.cmp(&a.0));
    let top_tokens: Vec<String> = top_tokens
        .into_iter()
        .take(opts.max_tokens)
        .map(|(_, k)| k.to_string())
        .collect();

    let url_regex = regex::Regex::new(r#"https?://[^\s<>"']+"#).unwrap();
    let email_regex = regex::Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap();
    let ip_regex = regex::Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b").unwrap();
    let path_regex =
        regex::Regex::new(r#"[A-Za-z]:\\(?:[^\\/:*?"<>|\s]+\\)*[^\\/:*?"<>|\s]+"#).unwrap();
    let base64_regex =
        regex::Regex::new(r"(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
            .unwrap();

    let combined_text = all_strings.join("\n");
    let combined_lower = combined_text.to_lowercase();

    let url_count = url_regex.find_iter(&combined_lower).count();
    let email_count = email_regex.find_iter(&combined_lower).count();
    let ip_count = ip_regex.find_iter(&combined_lower).count();
    let path_count = path_regex.find_iter(&combined_lower).count();
    let base64_count = base64_regex.find_iter(&combined_lower).count();

    let url_samples: Vec<String> = url_regex
        .find_iter(&combined_lower)
        .take(10)
        .map(|m| m.as_str().to_string())
        .collect();
    let email_samples: Vec<String> = email_regex
        .find_iter(&combined_lower)
        .take(10)
        .map(|m| m.as_str().to_string())
        .collect();
    let ip_samples: Vec<String> = ip_regex
        .find_iter(&combined_lower)
        .take(10)
        .map(|m| m.as_str().to_string())
        .collect();
    let path_samples: Vec<String> = path_regex
        .find_iter(&combined_lower)
        .take(10)
        .map(|m| m.as_str().to_string())
        .collect();
    let base64_samples: Vec<String> = base64_regex
        .find_iter(&combined_lower)
        .take(10)
        .map(|m| m.as_str().to_string())
        .collect();

    let total_chars = ascii_strings.iter().map(|s| s.len()).sum::<usize>()
        + utf16_strings.iter().map(|s| s.len()).sum::<usize>();

    let strings_text = if combined_text.len() > opts.max_output_chars {
        flags |= FLAG_TRUNCATED;
        combined_text.chars().take(opts.max_output_chars).collect()
    } else {
        combined_text
    };

    let mut warnings = Vec::new();
    if sampled {
        warnings.push("File was sampled (head + tail)".to_string());
    }
    if strings_text.len() >= opts.max_output_chars {
        warnings.push("Output truncated due to size limit".to_string());
    }

    ExtractedStrings {
        ascii_count: ascii_strings.len(),
        utf16_count: utf16_strings.len(),
        total_chars,
        truncated: flags & FLAG_TRUNCATED != 0,
        sampled,
        flags,
        strings_text,
        strings_json: StringsJson {
            ascii_count: ascii_strings.len(),
            utf16_count: utf16_strings.len(),
            total_chars,
            truncated: flags & FLAG_TRUNCATED != 0,
            sampled,
            tokens_count,
            top_tokens,
            url_count,
            email_count,
            ip_count,
            path_count,
            base64_count,
            url_samples,
            email_samples,
            ip_samples,
            path_samples,
            base64_samples,
            warnings,
        },
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileStringsResult {
    pub file_id: String,
    pub file_path: String,
    pub sha256: Option<String>,
    pub size_bytes: u64,
    pub extracted_utc: String,
    pub flags: u32,
    pub strings_text: String,
    pub strings_json: StringsJson,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_ascii_strings() {
        let data = b"Hello World\x00\x00Test String\x00Some Text Here\x00";
        let opts = StringsExtractOptions::default();
        let result = extract_strings(data, &opts);

        assert!(result.ascii_count >= 2);
        assert!(result.strings_text.contains("Hello World"));
        assert!(result.strings_text.contains("Test String"));
    }

    #[test]
    fn test_extract_min_length() {
        let data = b"ab\x00cd\x00";
        let opts = StringsExtractOptions::default();
        let result = extract_strings(data, &opts);

        assert_eq!(result.ascii_count, 0);
    }

    #[test]
    fn test_extract_utf16_strings() {
        let mut data = Vec::new();
        for c in "Hello!".chars() {
            data.push(c as u8);
            data.push(0);
        }
        data.push(0);
        data.push(0);

        let opts = StringsExtractOptions::default();
        let result = extract_strings(&data, &opts);

        assert!(result.utf16_count > 0);
        assert!(result.flags & FLAG_UTF16_PRESENT != 0);
    }

    #[test]
    fn test_gating_skips_images() {
        let opts = StringsExtractOptions::default();

        assert!(!should_extract_strings(
            "/path/to/file.jpg",
            1000,
            None,
            None,
            &opts
        ));
        assert!(!should_extract_strings(
            "/path/to/file.png",
            1000,
            None,
            None,
            &opts
        ));
        assert!(!should_extract_strings(
            "/path/to/file.mp4",
            1000,
            None,
            None,
            &opts
        ));
    }

    #[test]
    fn test_gating_allows_executables() {
        let opts = StringsExtractOptions::default();

        assert!(should_extract_strings(
            "/path/to/exe.exe",
            1000,
            Some("Executable"),
            None,
            &opts
        ));
        assert!(should_extract_strings(
            "/path/to/dll.dll",
            1000,
            Some("Executable"),
            None,
            &opts
        ));
    }

    #[test]
    fn test_gating_skips_high_entropy() {
        let opts = StringsExtractOptions::default();

        assert!(!should_extract_strings(
            "/path/to/file.bin",
            1000,
            None,
            Some(8.0),
            &opts
        ));
        assert!(should_extract_strings(
            "/path/to/file.bin",
            1000,
            None,
            Some(5.0),
            &opts
        ));
    }

    #[test]
    fn test_gating_skips_large_files() {
        let opts = StringsExtractOptions {
            max_file_size_bytes: 1000,
            sample_bytes: 500,
            ..Default::default()
        };

        assert!(!should_extract_strings(
            "/path/to/file.bin",
            2000,
            None,
            None,
            &opts
        ));
    }

    #[test]
    fn test_sampling_flag() {
        let opts = StringsExtractOptions {
            sample_bytes: 10,
            ..Default::default()
        };

        let data = vec![0u8; 100];
        let result = extract_strings(&data, &opts);

        assert!(result.sampled);
        assert!(result.flags & FLAG_SAMPLED != 0);
    }

    #[test]
    fn test_regex_detection_urls() {
        let data = b"Visit https://example.com for more info http://test.org";
        let opts = StringsExtractOptions::default();
        let result = extract_strings(data, &opts);

        assert!(result.strings_json.url_count >= 2);
        assert!(!result.strings_json.url_samples.is_empty());
    }

    #[test]
    fn test_regex_detection_emails() {
        let data = b"Contact test@example.com or admin@domain.org please";
        let opts = StringsExtractOptions::default();
        let result = extract_strings(data, &opts);

        assert!(result.strings_json.email_count >= 2);
    }

    #[test]
    fn test_regex_detection_ips() {
        let data = b"Server 192.168.1.1 and 10.0.0.1 are available";
        let opts = StringsExtractOptions::default();
        let result = extract_strings(data, &opts);

        assert!(result.strings_json.ip_count >= 2);
    }

    #[test]
    fn test_regex_detection_paths() {
        let data = b"Path C:\\Windows\\System32 and C:\\Users\\Admin";
        let opts = StringsExtractOptions::default();
        let result = extract_strings(data, &opts);

        assert!(result.strings_json.path_count >= 2);
    }

    #[test]
    fn test_output_truncation() {
        let data = vec![b'X'; 500000];
        let opts = StringsExtractOptions {
            max_output_chars: 1000,
            ..Default::default()
        };
        let result = extract_strings(&data, &opts);

        assert!(result.truncated);
        assert!(result.strings_text.len() <= 1000);
    }

    #[test]
    fn test_determinism() {
        let data = b"Some test string data here http://example.com test@example.com";
        let opts = StringsExtractOptions::default();

        let result1 = extract_strings(data, &opts);
        let result2 = extract_strings(data, &opts);

        assert_eq!(result1.ascii_count, result2.ascii_count);
        assert_eq!(result1.strings_text, result2.strings_text);
        assert_eq!(
            result1.strings_json.url_count,
            result2.strings_json.url_count
        );
        assert_eq!(
            result1.strings_json.email_count,
            result2.strings_json.email_count
        );
    }
}
