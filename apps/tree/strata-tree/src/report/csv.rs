// report/csv.rs — CSV export for file listings, bookmarks, and search results.
use anyhow::Result;
use std::path::Path;
use crate::state::{IndexedFile, Bookmark};

pub fn export_file_listing(files: &[IndexedFile], output_path: &Path) -> Result<()> {
    let mut out = String::from("id,path,name,extension,size,is_deleted,modified_utc,category,sha256\n");
    for f in files {
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{},{}\n",
            f.id,
            csv_escape(&f.path),
            csv_escape(&f.name),
            f.extension.as_deref().unwrap_or(""),
            f.size.map(|s| s.to_string()).unwrap_or_default(),
            f.is_deleted as u8,
            f.modified_utc.as_deref().unwrap_or(""),
            f.category.as_deref().unwrap_or(""),
            f.sha256.as_deref().unwrap_or(""),
        ));
    }
    std::fs::write(output_path, out)?;
    Ok(())
}

pub fn export_bookmarks(bookmarks: &[Bookmark], output_path: &Path) -> Result<()> {
    let mut out = String::from("id,file_id,examiner,label,color,created_utc,note\n");
    for b in bookmarks {
        out.push_str(&format!(
            "{},{},{},{},{},{},{}\n",
            b.id,
            b.file_id,
            csv_escape(&b.examiner),
            csv_escape(b.label.as_deref().unwrap_or("")),
            b.color.as_deref().unwrap_or(""),
            b.created_utc,
            csv_escape(b.note.as_deref().unwrap_or("")),
        ));
    }
    std::fs::write(output_path, out)?;
    Ok(())
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}
