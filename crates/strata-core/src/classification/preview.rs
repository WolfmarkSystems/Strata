use crate::errors::ForensicError;

pub fn generate_preview(
    data: &[u8],
    entry: &super::triage::TriageEntry,
) -> Result<FilePreview, ForensicError> {
    let preview_type = match &entry.extension {
        Some(ext) => match ext.to_lowercase().as_str() {
            "jpg" | "jpeg" | "png" | "gif" | "bmp" => PreviewType::Image,
            "txt" | "log" | "ini" | "cfg" | "xml" | "json" | "csv" => PreviewType::Text,
            "pdf" => PreviewType::Pdf,
            "exe" | "dll" | "sys" => PreviewType::Binary,
            _ => PreviewType::Hex,
        },
        None => PreviewType::Hex,
    };

    match preview_type {
        PreviewType::Image => generate_image_preview(data),
        PreviewType::Text => generate_text_preview(data),
        PreviewType::Pdf => generate_pdf_preview(data),
        PreviewType::Binary => generate_binary_info(data),
        PreviewType::Hex => generate_hex_preview(data),
    }
}

#[derive(Debug, Clone)]
pub enum PreviewType {
    Image,
    Text,
    Pdf,
    Binary,
    Hex,
}

#[derive(Debug, Clone)]
pub struct FilePreview {
    pub preview_type: PreviewType,
    pub content: PreviewContent,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub enum PreviewContent {
    Text(String),
    Image(ImagePreview),
    Binary(BinaryPreview),
    Hex(HexPreview),
    None,
}

#[derive(Debug, Clone)]
pub struct ImagePreview {
    pub width: u32,
    pub height: u32,
    pub format: String,
    pub thumbnail: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct BinaryPreview {
    pub magic: String,
    pub is_executable: bool,
    pub is_dll: bool,
    pub import_summary: Vec<String>,
    pub entropy: f64,
}

#[derive(Debug, Clone)]
pub struct HexPreview {
    pub offset: u64,
    pub hex_lines: Vec<HexLine>,
    pub ascii_preview: String,
}

#[derive(Debug, Clone)]
pub struct HexLine {
    pub offset: u64,
    pub hex_bytes: String,
    pub ascii: String,
}

fn generate_text_preview(data: &[u8]) -> Result<FilePreview, ForensicError> {
    let text = String::from_utf8_lossy(data);
    let preview = text.chars().take(4096).collect::<String>();

    Ok(FilePreview {
        preview_type: PreviewType::Text,
        content: PreviewContent::Text(preview),
        size: data.len() as u64,
    })
}

fn generate_image_preview(data: &[u8]) -> Result<FilePreview, ForensicError> {
    Ok(FilePreview {
        preview_type: PreviewType::Image,
        content: PreviewContent::Image(ImagePreview {
            width: 0,
            height: 0,
            format: "unknown".to_string(),
            thumbnail: None,
        }),
        size: data.len() as u64,
    })
}

fn generate_pdf_preview(data: &[u8]) -> Result<FilePreview, ForensicError> {
    let text = String::from_utf8_lossy(data);
    let preview = text.chars().take(4096).collect::<String>();

    Ok(FilePreview {
        preview_type: PreviewType::Pdf,
        content: PreviewContent::Text(preview),
        size: data.len() as u64,
    })
}

fn generate_binary_info(data: &[u8]) -> Result<FilePreview, ForensicError> {
    let magic = detect_magic(data);
    let entropy = super::triage::calculate_entropy(data);

    Ok(FilePreview {
        preview_type: PreviewType::Binary,
        content: PreviewContent::Binary(BinaryPreview {
            magic,
            is_executable: false,
            is_dll: false,
            import_summary: vec![],
            entropy,
        }),
        size: data.len() as u64,
    })
}

fn generate_hex_preview(data: &[u8]) -> Result<FilePreview, ForensicError> {
    let sample_size = 256.min(data.len());
    let sample = &data[..sample_size];

    let mut hex_lines = Vec::new();
    for (i, chunk) in sample.chunks(16).enumerate() {
        let offset = i as u64 * 16;

        let hex_bytes: String = chunk
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" ");

        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if (32..127).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();

        hex_lines.push(HexLine {
            offset,
            hex_bytes,
            ascii,
        });
    }

    let ascii_preview: String = sample
        .iter()
        .map(|&b| {
            if (32..127).contains(&b) {
                b as char
            } else {
                '.'
            }
        })
        .take(64)
        .collect();

    Ok(FilePreview {
        preview_type: PreviewType::Hex,
        content: PreviewContent::Hex(HexPreview {
            offset: 0,
            hex_lines,
            ascii_preview,
        }),
        size: data.len() as u64,
    })
}

fn detect_magic(data: &[u8]) -> String {
    if data.len() < 4 {
        return "Unknown".to_string();
    }

    match &data[..4] {
        b"MZ" => "PE/COFF (Windows Executable)".to_string(),
        b"\x7fELF" => "ELF (Linux Executable)".to_string(),
        b"ID3" | b"\xff\xfb" | b"\xff\xf3" | b"\xff\xf2" => "MP3 Audio".to_string(),
        b"\x89PNG" => "PNG Image".to_string(),
        b"\xff\xd8\xff" => "JPEG Image".to_string(),
        b"GIF8" => "GIF Image".to_string(),
        b"PK\x03\x04" => "ZIP Archive".to_string(),
        b"Rar!" => "RAR Archive".to_string(),
        b"\x1f\x8b" => "GZIP Archive".to_string(),
        b"%PDF" => "PDF Document".to_string(),
        b"DOC" => "MS Office Document".to_string(),
        _ => format!(
            "{:02X} {:02X} {:02X} {:02X}",
            data[0], data[1], data[2], data[3]
        ),
    }
}
