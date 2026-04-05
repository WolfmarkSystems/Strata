use crate::case::activity_log::ActivityLogger;
use crate::case::notes::NotesManager;
use std::io::Write;

pub fn export_notes_to_csv(manager: &NotesManager) -> Result<String, String> {
    let mut csv = String::new();
    csv.push_str("ID,Title,Content,Tags,Created,Modified,Reviewed,Reviewer\n");

    for note in manager.list_notes() {
        let tags = note.tags.join(";");
        csv.push_str(&format!(
            "\"{}\",\"{}\",\"{}\",\"{}\",{},{},{},\"{}\"\n",
            note.id,
            escape_csv(&note.title),
            escape_csv(&note.content),
            tags,
            note.created_at,
            note.modified_at,
            note.reviewed,
            note.reviewer.as_deref().unwrap_or("")
        ));
    }

    Ok(csv)
}

pub fn export_exhibits_to_csv(manager: &NotesManager) -> Result<String, String> {
    let mut csv = String::new();
    csv.push_str("ID,Name,Type,File Path,MD5,SHA1,SHA256,Tags,Created By,Created At\n");

    for exhibit in manager.list_exhibits() {
        let exhibit_type = match &exhibit.exhibit_type {
            crate::case::notes::ExhibitType::File => "File",
            crate::case::notes::ExhibitType::Image => "Image",
            crate::case::notes::ExhibitType::Text => "Text",
            crate::case::notes::ExhibitType::WebArchive => "WebArchive",
            crate::case::notes::ExhibitType::Email => "Email",
            crate::case::notes::ExhibitType::ChatMessage => "ChatMessage",
            crate::case::notes::ExhibitType::Document => "Document",
            crate::case::notes::ExhibitType::Registry => "Registry",
            crate::case::notes::ExhibitType::Memory => "Memory",
            crate::case::notes::ExhibitType::Custom(s) => s,
        };
        let tags = exhibit.tags.join(";");
        csv.push_str(&format!(
            "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",{}\n",
            exhibit.id,
            escape_csv(&exhibit.name),
            exhibit_type,
            exhibit.file_path.as_deref().unwrap_or(""),
            exhibit.hash_md5.as_deref().unwrap_or(""),
            exhibit.hash_sha1.as_deref().unwrap_or(""),
            exhibit.hash_sha256.as_deref().unwrap_or(""),
            tags,
            exhibit.created_by,
            exhibit.created_at
        ));
    }

    Ok(csv)
}

pub fn export_activity_to_csv(logger: &ActivityLogger) -> Result<String, String> {
    let mut csv = String::new();
    csv.push_str("ID,UTC Timestamp,Local Timestamp,Case ID,Evidence ID,User,Session ID,Event Type,Summary,Details\n");

    for event in logger.get_events() {
        let event_type = format!("{:?}", event.event_type);
        csv.push_str(&format!(
            "\"{}\",{},\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"\n",
            event.id,
            event.timestamp_utc,
            event.timestamp_local,
            event.case_id,
            event.evidence_id.as_deref().unwrap_or(""),
            event.user,
            event.session_id,
            event_type,
            escape_csv(&event.summary),
            escape_csv(&format_details(&event.details))
        ));
    }

    Ok(csv)
}

fn escape_csv(s: &str) -> String {
    s.replace('"', "\"\"")
}

fn format_details(details: &crate::case::activity_log::ActivityDetails) -> String {
    let mut parts = Vec::new();

    if let Some(ref filters) = details.filters {
        parts.push(format!("filters: {:?}", filters));
    }
    if let Some(ref query) = details.search_query {
        parts.push(format!("query: {}", query));
    }
    if let Some(count) = details.result_count {
        parts.push(format!("results: {}", count));
    }
    if let Some(ref module) = details.module_name {
        parts.push(format!("module: {}", module));
    }
    if let Some(ref export) = details.export_type {
        parts.push(format!("export: {}", export));
    }
    if let Some(ref view) = details.view_name {
        parts.push(format!("view: {}", view));
    }

    parts.join("; ")
}

pub fn export_notes_json(manager: &NotesManager) -> Result<String, String> {
    serde_json::to_string_pretty(&manager.list_notes()).map_err(|e| e.to_string())
}

pub fn export_exhibits_json(manager: &NotesManager) -> Result<String, String> {
    serde_json::to_string_pretty(&manager.list_exhibits()).map_err(|e| e.to_string())
}

pub fn export_activity_json(logger: &ActivityLogger) -> Result<String, String> {
    serde_json::to_string_pretty(logger.get_events()).map_err(|e| e.to_string())
}

pub fn export_full_report(
    manager: &NotesManager,
    logger: &ActivityLogger,
    case_name: &str,
) -> Result<String, String> {
    let mut report = String::new();

    report.push_str(&format!("# Forensic Case Report: {}\n\n", case_name));
    report.push_str("## Activity Log\n\n");
    report.push_str(&export_activity_to_csv(logger)?);
    report.push_str("\n\n## Notes\n\n");
    report.push_str(&export_notes_to_csv(manager)?);
    report.push_str("\n\n## Exhibits\n\n");
    report.push_str(&export_exhibits_to_csv(manager)?);

    Ok(report)
}

pub fn write_to_file(content: &str, path: &str) -> Result<(), String> {
    let mut file = std::fs::File::create(path).map_err(|e| e.to_string())?;
    file.write_all(content.as_bytes())
        .map_err(|e| e.to_string())?;
    Ok(())
}
