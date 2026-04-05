use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportConfig {
    pub format: ExportFormat,
    pub include_metadata: bool,
    pub include_hashes: bool,
    pub include_timeline: bool,
    pub include_volumes: bool,
    pub include_carved_files: bool,
    pub include_strings: bool,
    pub date_format: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExportFormat {
    JSON,
    CSV,
    XML,
    HTML,
    Markdown,
    PlainText,
}

impl Default for ExportConfig {
    fn default() -> Self {
        Self {
            format: ExportFormat::JSON,
            include_metadata: true,
            include_hashes: true,
            include_timeline: true,
            include_volumes: true,
            include_carved_files: false,
            include_strings: false,
            date_format: "%Y-%m-%d %H:%M:%S".to_string(),
        }
    }
}

pub fn export_to_json<T: serde::Serialize>(data: &T) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(data)
}

pub fn export_to_csv(headers: &[&str], rows: &[Vec<String>]) -> String {
    let mut output = String::new();

    output.push_str(&headers.join(","));
    output.push('\n');

    for row in rows {
        let escaped: Vec<String> = row
            .iter()
            .map(|s| format!("\"{}\"", s.replace('"', "\"\"")))
            .collect();
        output.push_str(&escaped.join(","));
        output.push('\n');
    }

    output
}

pub fn export_to_markdown(title: &str, sections: &[(&str, &str)]) -> String {
    let mut output = String::new();

    output.push_str(&format!("# {}\n\n", title));

    for (heading, content) in sections {
        output.push_str(&format!("## {}\n\n", heading));
        output.push_str(content);
        output.push_str("\n\n");
    }

    output
}

pub fn export_to_plaintext(title: &str, data: &HashMap<String, String>) -> String {
    let mut output = String::new();

    output.push_str(&format!("=== {} ===\n\n", title));

    for (key, value) in data {
        output.push_str(&format!("{}: {}\n", key, value));
    }

    output
}

pub fn export_to_xml(root: &str, data: &HashMap<String, String>) -> String {
    let mut output = String::new();

    output.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    output.push_str(&format!("<{}>\n", root));

    for (key, value) in data {
        let tag = key.replace(' ', "_").to_lowercase();
        output.push_str(&format!("  <{}>{}</{}>\n", tag, escape_xml(value), tag));
    }

    output.push_str(&format!("</{}>\n", root));

    output
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

pub fn convert_between_formats(
    input: &str,
    from: ExportFormat,
    to: ExportFormat,
) -> Result<String, String> {
    match (from, to) {
        (ExportFormat::JSON, ExportFormat::CSV) => {
            let data: HashMap<String, serde_json::Value> =
                serde_json::from_str(input).map_err(|e| e.to_string())?;

            let mut output = String::new();
            if let Some(first) = data.values().next() {
                if let Some(obj) = first.as_object() {
                    let headers: Vec<&str> = obj.keys().map(|s| s.as_str()).collect();
                    output.push_str(&headers.join(","));
                    output.push('\n');

                    for value in data.values() {
                        if let Some(obj) = value.as_object() {
                            let row: Vec<String> = obj.values().map(|v| v.to_string()).collect();
                            output.push_str(&row.join(","));
                            output.push('\n');
                        }
                    }
                }
            }
            Ok(output)
        }
        _ => Err("Conversion not implemented".to_string()),
    }
}
