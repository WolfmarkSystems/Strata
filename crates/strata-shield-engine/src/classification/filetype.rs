#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FileCategory {
    Image,
    Video,
    Audio,
    Document,
    Archive,
    Executable,
    Database,
    SourceCode,
    WebContent,
    Email,
    DiskImage,
    Unknown,
}

impl FileCategory {
    pub fn from_extension(ext: &str) -> Self {
        match ext.to_lowercase().as_str() {
            "jpg" | "jpeg" | "png" | "gif" | "bmp" | "tiff" | "tif" | "webp" | "svg" | "ico"
            | "raw" | "psd" | "ai" | "eps" => FileCategory::Image,
            "mp4" | "avi" | "mkv" | "mov" | "wmv" | "flv" | "webm" | "mpeg" | "mpg" | "m4v" => {
                FileCategory::Video
            }
            "mp3" | "wav" | "flac" | "aac" | "ogg" | "wma" | "m4a" | "aiff" => FileCategory::Audio,
            "doc" | "docx" | "pdf" | "txt" | "rtf" | "odt" | "xls" | "xlsx" | "ppt" | "pptx"
            | "csv" | "md" => FileCategory::Document,
            "zip" | "rar" | "7z" | "tar" | "gz" | "bz2" | "xz" | "iso" => FileCategory::Archive,
            "exe" | "dll" | "sys" | "msi" | "bat" | "cmd" | "ps1" | "sh" | "bin" => {
                FileCategory::Executable
            }
            "db" | "sqlite" | "sqlite3" | "mdb" | "accdb" | "dbf" => FileCategory::Database,
            "c" | "cpp" | "h" | "hpp" | "rs" | "py" | "js" | "ts" | "java" | "cs" | "go" | "rb"
            | "php" | "swift" | "kt" => FileCategory::SourceCode,
            "html" | "htm" | "css" | "json" | "xml" | "yaml" | "yml" => FileCategory::WebContent,
            "msg" | "eml" | "pst" | "ost" | "mbox" | "dbx" => FileCategory::Email,
            "img" | "dd" | "vmdk" | "vhd" | "vhdx" | "e01" | "aff" => FileCategory::DiskImage,
            _ => FileCategory::Unknown,
        }
    }

    pub fn from_magic_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }

        if data.starts_with(&[0xFF, 0xD8, 0xFF]) {
            return Some(FileCategory::Image);
        }
        if &data[0..4] == b"\x89PNG" {
            return Some(FileCategory::Image);
        }
        if &data[0..4] == b"GIF8" {
            return Some(FileCategory::Image);
        }
        if &data[0..4] == b"RIFF" && data.len() >= 12 && &data[8..12] == b"WEBP" {
            return Some(FileCategory::Image);
        }
        if &data[0..4] == b"BM" {
            return Some(FileCategory::Image);
        }
        if data.starts_with(b"%PDF") {
            return Some(FileCategory::Document);
        }
        if &data[0..2] == b"PK" {
            return Some(FileCategory::Archive);
        }
        if data.starts_with(&[0x1F, 0x8B]) {
            return Some(FileCategory::Archive);
        }
        if &data[0..4] == b"\x00\x00\x01\x00" || &data[0..2] == b"MZ" {
            return Some(FileCategory::Executable);
        }
        if &data[0..4] == b"SQLite" {
            return Some(FileCategory::Database);
        }

        None
    }

    pub fn as_str(&self) -> &str {
        match self {
            FileCategory::Image => "Image",
            FileCategory::Video => "Video",
            FileCategory::Audio => "Audio",
            FileCategory::Document => "Document",
            FileCategory::Archive => "Archive",
            FileCategory::Executable => "Executable",
            FileCategory::Database => "Database",
            FileCategory::SourceCode => "Source Code",
            FileCategory::WebContent => "Web Content",
            FileCategory::Email => "Email",
            FileCategory::DiskImage => "Disk Image",
            FileCategory::Unknown => "Unknown",
        }
    }
}

#[derive(Debug, Clone)]
pub struct MimeType {
    pub category: FileCategory,
    pub mime: String,
    pub extensions: Vec<String>,
}

impl MimeType {
    pub fn get_for_extension(ext: &str) -> Self {
        let category = FileCategory::from_extension(ext);
        let mime = match ext.to_lowercase().as_str() {
            "jpg" | "jpeg" => "image/jpeg",
            "png" => "image/png",
            "gif" => "image/gif",
            "bmp" => "image/bmp",
            "webp" => "image/webp",
            "pdf" => "application/pdf",
            "zip" => "application/zip",
            "rar" => "application/x-rar-compressed",
            "7z" => "application/x-7z-compressed",
            "exe" => "application/x-msdownload",
            "dll" => "application/x-msdownload",
            "mp3" => "audio/mpeg",
            "mp4" => "video/mp4",
            "html" => "text/html",
            "css" => "text/css",
            "js" => "application/javascript",
            "json" => "application/json",
            "xml" => "application/xml",
            "txt" => "text/plain",
            "csv" => "text/csv",
            _ => "application/octet-stream",
        }
        .to_string();

        Self {
            category,
            mime,
            extensions: vec![ext.to_string()],
        }
    }
}
