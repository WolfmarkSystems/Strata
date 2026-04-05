use crate::errors::ForensicError;
use std::fs;
use std::path::Path;

pub(crate) fn court_ready_inline_css() -> &'static str {
    r#"
        body { font-family: Arial, sans-serif; margin: 0; padding: 24px; background: #eef2f7; color: #1b2430; }
        .report-shell { max-width: 980px; margin: 0 auto; background: #ffffff; padding: 32px; border-radius: 12px; box-shadow: 0 10px 28px rgba(15, 23, 42, 0.08); }
        .report-header { border-bottom: 3px solid #1d4ed8; padding-bottom: 18px; margin-bottom: 28px; }
        .report-header h1 { margin: 0 0 14px 0; font-size: 30px; color: #10203a; }
        .meta-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; }
        .meta-card, .summary-card { background: #f8fafc; border: 1px solid #d7e2ef; border-radius: 10px; padding: 14px 16px; }
        .meta-label, .summary-label { display: block; font-size: 12px; text-transform: uppercase; letter-spacing: 0.06em; color: #5b6b7f; margin-bottom: 6px; }
        .meta-value { font-size: 15px; line-height: 1.4; }
        .report-section { margin-top: 24px; border: 1px solid #d7e2ef; border-radius: 10px; padding: 20px; background: #ffffff; }
        .report-section h2 { margin-top: 0; margin-bottom: 16px; color: #12325b; }
        .detail-table { width: 100%; border-collapse: collapse; }
        .detail-table th, .detail-table td { border: 1px solid #d7e2ef; padding: 10px 12px; text-align: left; vertical-align: top; }
        .detail-table th { width: 32%; background: #eff6ff; color: #12325b; }
        .mono { font-family: Consolas, 'Courier New', monospace; font-size: 12px; word-break: break-all; }
        .status-verified { color: #166534; font-weight: bold; }
        .status-unverified { color: #b91c1c; font-weight: bold; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; }
        .summary-value { font-size: 28px; font-weight: bold; color: #12325b; }
        .limitations { background: #fff7ed; border: 1px solid #fdba74; border-radius: 10px; padding: 16px; line-height: 1.5; }
        .signature-line { margin: 18px 0 0; font-size: 16px; }
    "#
}

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
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .section { background: white; margin: 20px 0; padding: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .section h2 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th { background: #3498db; color: white; padding: 10px; text-align: left; }
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
