use crate::errors::ForensicError;
use std::fs;
use std::path::Path;

pub struct ForensicReport {
    pub case_info: CaseInfo,
    pub sections: Vec<ReportSection>,
}

#[derive(Debug, Clone)]
pub struct CaseInfo {
    pub case_number: String,
    pub examiner: String,
    pub description: String,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct ReportSection {
    pub title: String,
    pub section_type: SectionType,
    pub content: String,
    pub table_data: Option<Vec<TableRow>>,
}

#[derive(Debug, Clone)]
pub enum SectionType {
    Text,
    Table,
    Image,
    Timeline,
    Summary,
}

#[derive(Debug, Clone)]
pub struct TableRow {
    pub headers: Vec<String>,
    pub values: Vec<Vec<String>>,
}

pub fn generate_html_report(report: &ForensicReport) -> String {
    let mut html = String::new();

    html.push_str(r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Forensic Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; color: #111622; }
        .header { background: #1a2e44; color: white; padding: 20px; border-radius: 5px; }
        .section { background: white; margin: 20px 0; padding: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .section h2 { color: #1a2e44; border-bottom: 2px solid #8fa8c0; padding-bottom: 10px; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th { background: #1a2e44; color: white; padding: 10px; text-align: left; }
        td { padding: 8px; border-bottom: 1px solid #ddd; }
        tr:hover { background: #f5f5f5; }
        .badge { display: inline-block; padding: 4px 8px; border-radius: 3px; font-size: 12px; }
        .badge-success { background: #27ae60; color: white; }
        .badge-warning { background: #f39c12; color: white; }
        .badge-danger { background: #e74c3c; color: white; }
        .timestamp { color: #7f8c8d; font-size: 12px; }
    </style>
</head>
<body>
"#);

    html.push_str(&format!(
        r#"
    <div class="header">
        <h1>Forensic Analysis Report</h1>
        <p>Case: {} | Examiner: {}</p>
        <p class="timestamp">Generated: {}</p>
    </div>
"#,
        report.case_info.case_number,
        report.case_info.examiner,
        format_time(report.case_info.created_at)
    ));

    for section in &report.sections {
        html.push_str(&format!(
            "<div class=\"section\"><h2>{}</h2>",
            section.title
        ));

        match section.section_type {
            SectionType::Text => {
                html.push_str(&format!("<p>{}</p>", section.content));
            }
            SectionType::Table => {
                if let Some(ref table) = section.table_data {
                    if !table.is_empty() {
                        html.push_str("<table><thead><tr>");
                        for header in &table[0].headers {
                            html.push_str(&format!("<th>{}</th>", header));
                        }
                        html.push_str("</tr></thead><tbody>");

                        for row in table {
                            for cell in &row.values {
                                html.push_str("<tr>");
                                for cell_val in cell {
                                    html.push_str(&format!("<td>{}</td>", cell_val));
                                }
                                html.push_str("</tr>");
                            }
                        }
                        html.push_str("</tbody></table>");
                    }
                }
            }
            SectionType::Summary => {
                html.push_str(&format!("<p>{}</p>", section.content));
            }
            _ => {}
        }

        html.push_str("</div>");
    }

    html.push_str("</body></html>");
    html
}

fn format_time(timestamp: i64) -> String {
    use time::{OffsetDateTime, UtcOffset};

    if timestamp <= 0 {
        return "N/A".to_string();
    }

    if let Ok(dt) = OffsetDateTime::from_unix_timestamp(timestamp) {
        let formatted = dt
            .to_offset(UtcOffset::UTC)
            .format(&time::format_description::well_known::Rfc3339);
        formatted.unwrap_or_else(|_| timestamp.to_string())
    } else {
        timestamp.to_string()
    }
}

pub fn generate_summary_report(
    total_files: usize,
    total_size: u64,
    _file_types: &[(String, usize)],
    suspicious_files: usize,
    timeline_events: usize,
) -> String {
    let total_mb = total_size / 1024 / 1024;

    format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Executive Summary</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .summary {{ background: white; padding: 30px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .stat-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
        .stat-box {{ background: #ecf0f1; padding: 20px; border-radius: 5px; text-align: center; }}
        .stat-number {{ font-size: 36px; font-weight: bold; color: #2c3e50; }}
        .stat-label {{ color: #7f8c8d; margin-top: 10px; }}
    </style>
</head>
<body>
    <div class="summary">
        <h1>Executive Summary</h1>
        <div class="stat-grid">
            <div class="stat-box">
                <div class="stat-number">{}</div>
                <div class="stat-label">Total Files</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{}</div>
                <div class="stat-label">Total Size (MB)</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{}</div>
                <div class="stat-label">Suspicious Files</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{}</div>
                <div class="stat-label">Timeline Events</div>
            </div>
        </div>
    </div>
</body>
</html>"#,
        total_files, total_mb, suspicious_files, timeline_events
    )
}

pub fn save_report(report: &ForensicReport, output_path: &Path) -> Result<(), ForensicError> {
    let html = generate_html_report(report);
    strata_fs::write(output_path, html)?;
    Ok(())
}
