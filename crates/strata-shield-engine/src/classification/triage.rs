#[derive(Debug, Clone)]
pub struct TriageEntry {
    pub id: u64,
    pub path: String,
    pub name: String,
    pub size: u64,
    pub created: Option<u64>,
    pub modified: Option<u64>,
    pub accessed: Option<u64>,
    pub is_directory: bool,
    pub is_hidden: bool,
    pub is_system: bool,
    pub extension: Option<String>,
    pub entropy: Option<f64>,
    pub file_category: FileCategory,
    pub hash_results: Vec<HashResult>,
    pub is_known: bool,
    pub known_source: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub enum FileCategory {
    #[default]
    Unknown,
    Document,
    Image,
    Video,
    Audio,
    Archive,
    Executable,
    Database,
    SourceCode,
    WebContent,
    Email,
    Chat,
    System,
    Config,
    Log,
    Temp,
    Cache,
}

impl FileCategory {
    pub fn from_extension(ext: &str) -> Self {
        match ext.to_lowercase().as_str() {
            "doc" | "docx" | "odt" | "rtf" | "txt" | "pdf" | "xls" | "xlsx" | "ppt" | "pptx" => {
                FileCategory::Document
            }
            "jpg" | "jpeg" | "png" | "gif" | "bmp" | "tiff" | "webp" | "svg" => FileCategory::Image,
            "mp4" | "avi" | "mkv" | "mov" | "wmv" | "flv" | "webm" => FileCategory::Video,
            "mp3" | "wav" | "flac" | "aac" | "ogg" | "wma" => FileCategory::Audio,
            "zip" | "rar" | "7z" | "tar" | "gz" | "bz2" => FileCategory::Archive,
            "exe" | "dll" | "sys" | "msi" | "bat" | "cmd" | "ps1" => FileCategory::Executable,
            "db" | "sqlite" | "mdb" | "accdb" => FileCategory::Database,
            "c" | "cpp" | "h" | "py" | "js" | "java" | "rs" | "go" => FileCategory::SourceCode,
            "html" | "htm" | "css" | "json" | "xml" => FileCategory::WebContent,
            "msg" | "eml" | "pst" | "ost" => FileCategory::Email,
            _ => FileCategory::Unknown,
        }
    }
}

#[derive(Debug, Clone)]
pub struct HashResult {
    pub hash_type: HashAlgorithm,
    pub value: String,
    pub matched: bool,
    pub source: Option<String>,
}

#[derive(Debug, Clone)]
pub enum HashAlgorithm {
    Md5,
    Sha1,
    Sha256,
}

pub fn create_triage_entry(
    path: &str,
    name: &str,
    size: u64,
    created: Option<u64>,
    modified: Option<u64>,
    accessed: Option<u64>,
    is_directory: bool,
) -> TriageEntry {
    let extension = if is_directory {
        None
    } else {
        name.rsplit('.').next().map(|s| s.to_lowercase())
    };

    let file_category = match &extension {
        Some(ext) => FileCategory::from_extension(ext),
        None => FileCategory::Unknown,
    };

    TriageEntry {
        id: 0,
        path: path.to_string(),
        name: name.to_string(),
        size,
        created,
        modified,
        accessed,
        is_directory,
        is_hidden: false,
        is_system: false,
        extension,
        entropy: None,
        file_category,
        hash_results: vec![],
        is_known: false,
        known_source: None,
    }
}

pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

pub fn is_high_entropy(data: &[u8], threshold: f64) -> bool {
    calculate_entropy(data) > threshold
}
