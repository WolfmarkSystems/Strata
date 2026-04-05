use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::case::database::CaseDatabase;
use crate::case::replay::get_latest_replay_report;
use crate::case::verify::get_latest_verification;

const TEMPLATE_FILE_MAX_BYTES: u64 = 1024 * 1024;

fn read_template_file(path: &std::path::Path) -> anyhow::Result<String> {
    let meta = std::fs::metadata(path)?;
    if meta.len() > TEMPLATE_FILE_MAX_BYTES {
        return Err(anyhow::anyhow!(
            "template file too large ({} bytes > {} bytes): {}",
            meta.len(),
            TEMPLATE_FILE_MAX_BYTES,
            path.display()
        ));
    }
    Ok(std::fs::read_to_string(path)?)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSkeleton {
    pub generated_utc: String,
    pub case_id: String,
    pub output_dir: String,
    pub files_created: Vec<String>,
}

pub fn generate_report_skeleton(
    case_id: &str,
    output_dir: &str,
    db: Option<&CaseDatabase>,
) -> anyhow::Result<ReportSkeleton> {
    let output_path = PathBuf::from(output_dir);
    std::fs::create_dir_all(&output_path)?;

    let now = chrono::Utc::now().to_rfc3339();
    let mut files_created = Vec::new();

    let templates_dir = std::path::Path::new("templates/reports");
    let template_files = vec![
        "report_header.md",
        "findings.md",
        "methodology.md",
        "glossary.md",
        "appendix.md",
    ];

    for template_file in template_files {
        let src = templates_dir.join(template_file);
        if src.exists() {
            let content = read_template_file(&src)?;
            let mut filled_content = content
                .replace("{{case_id}}", case_id)
                .replace("{{generated_utc}}", &now)
                .replace("{{tool_version}}", env!("CARGO_PKG_VERSION"))
                .replace("{{schema_version}}", "1.0")
                .replace("{{preset_name}}", "Standard Examiner")
                .replace("{{preset_description}}", "Default examination preset");

            if let Some(database) = db {
                let conn = database.get_connection();
                let mut conn = conn.lock().unwrap();

                if let Ok(Some(verify_report)) = get_latest_verification(&mut conn, case_id) {
                    filled_content = filled_content.replace(
                        "{{verification_status}}",
                        &format!("{:?}", verify_report.status),
                    );
                } else {
                    filled_content = filled_content.replace("{{verification_status}}", "N/A");
                }

                if let Ok(Some(replay_report)) = get_latest_replay_report(&mut conn, case_id) {
                    filled_content = filled_content
                        .replace("{{replay_status}}", &format!("{:?}", replay_report.status));
                } else {
                    filled_content = filled_content.replace("{{replay_status}}", "N/A");
                }

                let violations_count: i64 = conn
                    .query_row(
                        "SELECT COUNT(*) FROM integrity_violations WHERE case_id = ?1",
                        [case_id],
                        |row| row.get(0),
                    )
                    .unwrap_or(0);
                filled_content =
                    filled_content.replace("{{violations_count}}", &violations_count.to_string());

                let mut settings = String::new();
                let mut stmt =
                    conn.prepare("SELECT key, value FROM case_settings WHERE case_id = ?1")?;
                let rows = stmt.query_map([case_id], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
                })?;
                for row in rows.flatten() {
                    settings.push_str(&format!("{}: {}\n", row.0, row.1.unwrap_or_default()));
                }
                filled_content = filled_content.replace("{{case_settings}}", &settings);
            }

            filled_content = filled_content.replace("{{os_version}}", "Windows");
            filled_content = filled_content.replace("{{architecture}}", std::env::consts::ARCH);
            filled_content = filled_content.replace("{{webview2_status}}", "N/A");
            filled_content = filled_content.replace("{{build_date}}", &now);

            let dest = output_path.join(template_file);
            std::fs::write(&dest, filled_content)?;
            files_created.push(template_file.to_string());
        }
    }

    let summary_json = serde_json::json!({
        "case_id": case_id,
        "generated_utc": now,
        "tool_version": env!("CARGO_PKG_VERSION"),
        "files": files_created,
    });

    let summary_path = output_path.join("report_summary.json");
    std::fs::write(
        &summary_path,
        serde_json::to_string_pretty(&summary_json).unwrap_or_default(),
    )?;
    files_created.push("report_summary.json".to_string());

    Ok(ReportSkeleton {
        generated_utc: now,
        case_id: case_id.to_string(),
        output_dir: output_dir.to_string(),
        files_created,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_generate_report_skeleton() {
        let temp_dir = tempfile::tempdir().unwrap();

        let result = generate_report_skeleton("test_case", temp_dir.path().to_str().unwrap(), None);

        assert!(result.is_ok() || !temp_dir.path().exists());
    }

    #[test]
    fn test_read_template_file_rejects_oversized_input() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("too_large.md");
        let mut file = std::fs::File::create(&path).unwrap();
        let oversized = vec![b'a'; (TEMPLATE_FILE_MAX_BYTES as usize) + 1];
        file.write_all(&oversized).unwrap();

        let result = read_template_file(&path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too large"));
    }
}
