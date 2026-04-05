use serde::{Deserialize, Serialize};

pub mod csv;
pub mod export;
pub mod generator;
pub mod html;
pub mod json;
pub mod jsonl;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportConfig {
    pub title: String,
    pub author: String,
    pub case_number: Option<String>,
    pub include_timeline: bool,
    pub include_hashes: bool,
    pub include_volumes: bool,
    pub include_files: bool,
    pub include_strings: bool,
    pub include_carved: bool,
    pub include_phone_artifacts: bool,
    pub include_xways_view: bool,
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            title: "Forensic Analysis Report".to_string(),
            author: "Forensic Suite".to_string(),
            case_number: None,
            include_timeline: true,
            include_hashes: true,
            include_volumes: true,
            include_files: false,
            include_strings: false,
            include_carved: false,
            include_phone_artifacts: true,
            include_xways_view: true,
        }
    }
}

pub fn generate_html_report(config: &ReportConfig, data: &ReportData) -> String {
    let mut html = String::new();

    html.push_str(
        r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>"#,
    );
    html.push_str(&config.title);
    html.push_str(r#"</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 3px solid #0066cc; padding-bottom: 10px; }
        h2 { color: #555; margin-top: 30px; }
        .meta { background: #f0f0f0; padding: 15px; border-radius: 4px; margin: 20px 0; }
        .meta-item { margin: 5px 0; }
        .label { font-weight: bold; color: #666; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #0066cc; color: white; }
        tr:hover { background: #f5f5f5; }
        .hash { font-family: monospace; font-size: 12px; word-break: break-all; }
        .warning { background: #fff3cd; border: 1px solid #ffc107; padding: 10px; border-radius: 4px; }
        .success { background: #d4edda; border: 1px solid #28a745; padding: 10px; border-radius: 4px; }
        footer { margin-top: 40px; text-align: center; color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
"#);

    html.push_str("        <h1>");
    html.push_str(&config.title);
    html.push_str("</h1>\n");

    html.push_str("        <div class=\"meta\">\n");
    if let Some(case_num) = &config.case_number {
        html.push_str(&format!("            <div class=\"meta-item\"><span class=\"label\">Case Number:</span> {}</div>\n", case_num));
    }
    html.push_str(&format!(
        "            <div class=\"meta-item\"><span class=\"label\">Evidence:</span> {}</div>\n",
        data.evidence_path
    ));
    html.push_str(&format!(
        "            <div class=\"meta-item\"><span class=\"label\">Image Size:</span> {}</div>\n",
        data.image_size
    ));
    html.push_str(&format!(
        "            <div class=\"meta-item\"><span class=\"label\">Disk Layout:</span> {}</div>\n",
        data.disk_layout
    ));
    html.push_str("        </div>\n");

    if config.include_hashes {
        html.push_str("        <h2>Cryptographic Hashes</h2>\n");
        html.push_str("        <table>\n");
        html.push_str("            <tr><th>Algorithm</th><th>Hash</th></tr>\n");
        if let Some(ref md5) = data.md5 {
            html.push_str(&format!(
                "            <tr><td>MD5</td><td class=\"hash\">{}</td></tr>\n",
                md5
            ));
        }
        if let Some(ref sha1) = data.sha1 {
            html.push_str(&format!(
                "            <tr><td>SHA1</td><td class=\"hash\">{}</td></tr>\n",
                sha1
            ));
        }
        if let Some(ref sha256) = data.sha256 {
            html.push_str(&format!(
                "            <tr><td>SHA256</td><td class=\"hash\">{}</td></tr>\n",
                sha256
            ));
        }
        html.push_str("        </table>\n");
    }

    if config.include_volumes && !data.volumes.is_empty() {
        html.push_str("        <h2>Volumes</h2>\n");
        html.push_str("        <table>\n");
        html.push_str("            <tr><th>Index</th><th>Offset</th><th>Size</th><th>Type</th><th>File System</th></tr>\n");
        for vol in &data.volumes {
            html.push_str(&format!(
                "            <tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                vol.index, vol.offset, vol.size, vol.kind, vol.filesystem
            ));
        }
        html.push_str("        </table>\n");
    }

    if config.include_timeline && !data.timeline_entries.is_empty() {
        html.push_str("        <h2>Timeline (First 100 Entries)</h2>\n");
        html.push_str("        <table>\n");
        html.push_str(
            "            <tr><th>Timestamp</th><th>Action</th><th>Path</th><th>Size</th></tr>\n",
        );
        for entry in data.timeline_entries.iter().take(100) {
            html.push_str(&format!(
                "            <tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                entry.timestamp, entry.action, entry.path, entry.size
            ));
        }
        html.push_str("        </table>\n");
    }

    if config.include_carved && !data.carved_files.is_empty() {
        html.push_str("        <h2>Carved Files</h2>\n");
        html.push_str("        <table>\n");
        html.push_str("            <tr><th>Offset</th><th>Type</th><th>Confidence</th></tr>\n");
        for file in &data.carved_files {
            html.push_str(&format!(
                "            <tr><td>{}</td><td>{}</td><td>{}%</td></tr>\n",
                file.offset,
                file.extension,
                (file.confidence * 100.0) as u32
            ));
        }
        html.push_str("        </table>\n");
    }

    html.push_str(&format!(
        "
        <footer>
            <p>Generated by {} v{}</p>
            <p>Audit Hash: {}</p>
        </footer>
    </div>
</body>
</html>",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        data.audit_hash
    ));

    html
}

#[derive(Debug, Clone)]
pub struct ReportData {
    pub evidence_path: String,
    pub image_size: String,
    pub disk_layout: String,
    pub md5: Option<String>,
    pub sha1: Option<String>,
    pub sha256: Option<String>,
    pub audit_hash: String,
    pub volumes: Vec<VolumeReportEntry>,
    pub timeline_entries: Vec<TimelineReportEntry>,
    pub carved_files: Vec<CarvedReportEntry>,
}

#[derive(Debug, Clone)]
pub struct VolumeReportEntry {
    pub index: u32,
    pub offset: String,
    pub size: String,
    pub kind: String,
    pub filesystem: String,
}

#[derive(Debug, Clone)]
pub struct TimelineReportEntry {
    pub timestamp: String,
    pub action: String,
    pub path: String,
    pub size: String,
}

#[derive(Debug, Clone)]
pub struct CarvedReportEntry {
    pub offset: u64,
    pub extension: String,
    pub confidence: f32,
}

const REPORT_TEMPLATE_MAX_BYTES: u64 = 1024 * 1024;

fn read_template_or_fallback(path: &std::path::Path, fallback: &str) -> String {
    let Ok(meta) = std::fs::metadata(path) else {
        return fallback.to_string();
    };

    if meta.len() > REPORT_TEMPLATE_MAX_BYTES {
        return fallback.to_string();
    }

    std::fs::read_to_string(path).unwrap_or_else(|_| fallback.to_string())
}

pub fn generate_report_skeleton(
    case_id: &str,
    db_path: &std::path::Path,
    output_dir: &std::path::Path,
) -> anyhow::Result<std::collections::HashMap<String, std::path::PathBuf>> {
    use std::fs;
    use std::io::Write;

    let mut paths = std::collections::HashMap::new();

    strata_fs::create_dir_all(output_dir)?;

    let db = crate::case::database::CaseDatabase::open(case_id, db_path)?;

    let now = chrono::Utc::now().to_rfc3339();

    let mut report_content = String::new();
    report_content.push_str("# Forensic Analysis Report\n\n");
    report_content.push_str(&format!("Generated: {}\n", now));
    report_content.push_str(&format!("Case ID: {}\n\n", case_id));

    report_content.push_str("---\n\n");
    report_content.push_str(&read_template_or_fallback(
        &output_dir.join("report_header.md"),
        "# Case Information\n\n",
    ));
    report_content.push_str("\n---\n\n");

    let conn = db.get_connection();
    let mut conn = conn.lock().unwrap();
    let verification = crate::case::verify::get_latest_verification(&mut conn, case_id);
    if let Ok(Some(ver)) = verification {
        report_content.push_str("## Verification Summary\n\n");
        report_content.push_str(&format!("- Status: {:?}\n", ver.status));
        report_content.push_str(&format!("- Started (UTC): {}\n", ver.started_utc));
        report_content.push_str(&format!("- Finished (UTC): {}\n", ver.finished_utc));
        report_content.push('\n');
    }

    let replay = crate::case::replay::get_latest_replay_report(&mut conn, case_id);
    if let Ok(Some(rp)) = replay {
        report_content.push_str("## Replay Summary\n\n");
        report_content.push_str(&format!("- Status: {:?}\n", rp.status));
        report_content.push_str(&format!("- Started (UTC): {}\n", rp.started_utc));
        report_content.push_str(&format!("- Finished (UTC): {}\n", rp.finished_utc));
        report_content.push('\n');
    }

    let violations = crate::case::watchpoints::list_integrity_violations(&conn, case_id, None, 100);
    if let Ok(vs) = violations {
        if !vs.is_empty() {
            report_content.push_str("## Integrity Violations\n\n");
            for v in vs.iter().take(10) {
                report_content.push_str(&format!(
                    "- {}: {} (id={} at {})\n",
                    v.table_name, v.operation, v.id, v.occurred_utc
                ));
            }
            report_content.push('\n');
        }
    }

    report_content.push_str("---\n\n");
    report_content.push_str(&read_template_or_fallback(
        &output_dir.join("methodology.md"),
        "# Methodology\n\nAnalysis performed using forensic suite tools.\n\n",
    ));
    report_content.push_str("\n---\n\n");
    report_content.push_str(&read_template_or_fallback(
        &output_dir.join("findings.md"),
        "# Findings\n\n## Artifacts Identified\n\nNo specific findings documented.\n\n",
    ));
    report_content.push_str("\n---\n\n");
    report_content.push_str(&read_template_or_fallback(
        &output_dir.join("glossary.md"),
        "# Glossary\n\n| Term | Definition |\n|------|------------|\n| MFT | Master File Table (NTFS) |\n| IOC | Indicator of Compromise |\n\n",
    ));
    report_content.push_str("\n---\n\n");
    report_content.push_str(&read_template_or_fallback(
        &output_dir.join("appendix.md"),
        "# Appendix\n\n## Evidence Details\n\nCase ID: {case_id}\n\n",
    ));

    let report_path = output_dir.join("report.md");
    let mut file = strata_fs::File::create(&report_path)?;
    file.write_all(report_content.as_bytes())?;
    paths.insert("report".to_string(), report_path);

    let template_dir = std::path::Path::new("templates/reports");
    if template_dir.exists() {
        for entry in strata_fs::read_dir(template_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map(|e| e == "md").unwrap_or(false) {
                let name = path.file_stem().unwrap().to_str().unwrap().to_string();
                let dest = output_dir.join(path.file_name().unwrap());
                if !dest.exists() {
                    strata_fs::copy(&path, &dest)?;
                    paths.insert(name, dest);
                }
            }
        }
    }

    Ok(paths)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullCaseReport {
    pub case_id: String,
    pub generated_utc: String,
    pub summary_stats: CaseSummaryStats,
    pub html_content: Option<String>,
    pub tree_summary: TreeSummary,
    pub timeline_entries_count: usize,
    pub carved_files_count: usize,
    pub memory_processes_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CaseSummaryStats {
    pub total_files: usize,
    pub total_directories: usize,
    pub total_hashes_computed: usize,
    pub total_timeline_entries: usize,
    pub total_carved_files: usize,
    pub total_memory_processes: usize,
    pub total_volumes: usize,
    pub total_strings_extracted: usize,
    pub hash_category_breakdown: HashCategoryBreakdown,
    pub categories: std::collections::HashMap<String, usize>,
    pub loaded_plugins: usize,
    pub plugin_artifacts: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HashCategoryBreakdown {
    pub known_good: usize,
    pub known_bad: usize,
    pub known_unknown: usize,
    pub changed: usize,
    pub new_files: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeSummary {
    pub total_nodes: usize,
    pub visible_by_default: usize,
    pub categories: std::collections::HashMap<String, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PhoneArtifactSummary {
    pub total_phone_artifacts: usize,
    pub graykey_artifacts: usize,
    pub cellebrite_artifacts: usize,
    pub itunes_artifacts: usize,
    pub adb_artifacts: usize,
    pub axiom_artifacts: usize,
    pub whatsapp_messages: usize,
    pub imessage_messages: usize,
    pub signal_messages: usize,
    pub location_points: usize,
    pub call_logs: usize,
    pub contacts: usize,
    pub photos: usize,
    pub browser_history: usize,
    pub health_data: usize,
}

impl PhoneArtifactSummary {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn categorize_artifact(&mut self, artifact_type: &str) {
        self.total_phone_artifacts += 1;

        match artifact_type.to_lowercase().as_str() {
            "graykey" | "graykey extraction" => self.graykey_artifacts += 1,
            "cellebrite" | "ufed" => self.cellebrite_artifacts += 1,
            "ios_backup" | "itunes" | "iphone" | "icloud" => self.itunes_artifacts += 1,
            "android_backup" | "adb" | "android" => self.adb_artifacts += 1,
            "axiom" | "magnet" => self.axiom_artifacts += 1,
            "whatsapp" | "whatsapp message" => self.whatsapp_messages += 1,
            "imessage" | "ios message" => self.imessage_messages += 1,
            "signal" => self.signal_messages += 1,
            "location" | "gps" | "coordinates" => self.location_points += 1,
            "call" | "call log" => self.call_logs += 1,
            "contact" | "addressbook" => self.contacts += 1,
            "photo" | "image" | "media" => self.photos += 1,
            "browser" | "history" | "bookmark" => self.browser_history += 1,
            "health" | "workout" | "heart rate" => self.health_data += 1,
            _ => {}
        }
    }

    pub fn to_html(&self) -> String {
        let mut html = String::new();
        html.push_str("        <h2>Phone Acquisition Summary</h2>\n");
        html.push_str("        <table>\n");
        html.push_str("            <tr><th>Category</th><th>Count</th></tr>\n");
        html.push_str(&format!(
            "            <tr><td>Total Phone Artifacts</td><td>{}</td></tr>\n",
            self.total_phone_artifacts
        ));
        html.push_str(&format!(
            "            <tr><td>GrayKey Artifacts</td><td>{}</td></tr>\n",
            self.graykey_artifacts
        ));
        html.push_str(&format!(
            "            <tr><td>Cellebrite UFED Artifacts</td><td>{}</td></tr>\n",
            self.cellebrite_artifacts
        ));
        html.push_str(&format!(
            "            <tr><td>iTunes/iCloud Artifacts</td><td>{}</td></tr>\n",
            self.itunes_artifacts
        ));
        html.push_str(&format!(
            "            <tr><td>ADB Android Artifacts</td><td>{}</td></tr>\n",
            self.adb_artifacts
        ));
        html.push_str(&format!(
            "            <tr><td>Magnet AXIOM Artifacts</td><td>{}</td></tr>\n",
            self.axiom_artifacts
        ));
        html.push_str(&format!(
            "            <tr><td>WhatsApp Messages</td><td>{}</td></tr>\n",
            self.whatsapp_messages
        ));
        html.push_str(&format!(
            "            <tr><td>iMessages</td><td>{}</td></tr>\n",
            self.imessage_messages
        ));
        html.push_str(&format!(
            "            <tr><td>Signal Messages</td><td>{}</td></tr>\n",
            self.signal_messages
        ));
        html.push_str(&format!(
            "            <tr><td>Location Points</td><td>{}</td></tr>\n",
            self.location_points
        ));
        html.push_str(&format!(
            "            <tr><td>Call Logs</td><td>{}</td></tr>\n",
            self.call_logs
        ));
        html.push_str(&format!(
            "            <tr><td>Contacts</td><td>{}</td></tr>\n",
            self.contacts
        ));
        html.push_str(&format!(
            "            <tr><td>Photos/Media</td><td>{}</td></tr>\n",
            self.photos
        ));
        html.push_str(&format!(
            "            <tr><td>Browser History</td><td>{}</td></tr>\n",
            self.browser_history
        ));
        html.push_str(&format!(
            "            <tr><td>Health Data</td><td>{}</td></tr>\n",
            self.health_data
        ));
        html.push_str("        </table>\n");
        html
    }
}

pub fn generate_phone_report(
    _config: &ReportConfig,
    phone_summary: &PhoneArtifactSummary,
) -> String {
    let mut html = String::new();
    html.push_str(
        r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Phone Acquisition Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; }
        h1 { color: #333; border-bottom: 3px solid #0066cc; padding-bottom: 10px; }
        h2 { color: #555; margin-top: 30px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #0066cc; color: white; }
        tr:hover { background: #f5f5f5; }
        .summary-box { background: #e7f3ff; padding: 20px; border-radius: 8px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Phone Acquisition Report</h1>
"#,
    );
    html.push_str("        <div class=\"summary-box\">\n");
    html.push_str(&format!(
        "            <h3>Total Artifacts: {}</h3>\n",
        phone_summary.total_phone_artifacts
    ));
    html.push_str(&format!("            <p>Acquisition Types: GrayKey={}, Cellebrite={}, iTunes={}, ADB={}, AXIOM={}</p>\n",
        phone_summary.graykey_artifacts,
        phone_summary.cellebrite_artifacts,
        phone_summary.itunes_artifacts,
        phone_summary.adb_artifacts,
        phone_summary.axiom_artifacts));
    html.push_str("        </div>\n");
    html.push_str(&phone_summary.to_html());
    html.push_str("    </div>\n</body>\n</html>");
    html
}
