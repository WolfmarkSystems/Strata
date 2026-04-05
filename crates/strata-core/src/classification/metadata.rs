use crate::errors::ForensicError;
use std::fs;
use std::io::Read;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct MetadataCollection {
    pub file_path: String,
    pub metadata_items: Vec<MetadataItem>,
}

#[derive(Debug, Clone)]
pub struct MetadataItem {
    pub name: String,
    pub value: String,
    pub source: MetadataSource,
}

#[derive(Debug, Clone)]
pub enum MetadataSource {
    FileSystem,
    EXIF,
    Office,
    PDF,
    NTFS,
    AlternateDataStream,
    ExtendedAttribute,
}

pub fn collect_all_metadata(path: &Path) -> Result<MetadataCollection, ForensicError> {
    let mut items = Vec::new();
    let path_str = path.display().to_string();

    if let Ok(meta) = strata_fs::metadata(path) {
        if let Ok(created) = meta.created() {
            items.push(MetadataItem {
                name: "Created".to_string(),
                value: created
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs().to_string())
                    .unwrap_or_default(),
                source: MetadataSource::FileSystem,
            });
        }

        if let Ok(modified) = meta.modified() {
            items.push(MetadataItem {
                name: "Modified".to_string(),
                value: modified
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs().to_string())
                    .unwrap_or_default(),
                source: MetadataSource::FileSystem,
            });
        }

        if let Ok(accessed) = meta.accessed() {
            items.push(MetadataItem {
                name: "Accessed".to_string(),
                value: accessed
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs().to_string())
                    .unwrap_or_default(),
                source: MetadataSource::FileSystem,
            });
        }

        items.push(MetadataItem {
            name: "Size".to_string(),
            value: meta.len().to_string(),
            source: MetadataSource::FileSystem,
        });

        items.push(MetadataItem {
            name: "IsHidden".to_string(),
            value: path
                .file_name()
                .map(|n| n.to_string_lossy().starts_with('.').to_string())
                .unwrap_or_default(),
            source: MetadataSource::FileSystem,
        });
    }

    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    if ext == "jpg" || ext == "jpeg" || ext == "png" || ext == "tiff" {
        if let Ok(data) =
            super::scalpel::read_prefix(path, super::scalpel::DEFAULT_BINARY_MAX_BYTES)
        {
            if let Some(exif_items) = extract_basic_exif(&data) {
                items.extend(exif_items);
            }
        }
    }

    if ext == "pdf" {
        if let Ok(data) =
            super::scalpel::read_prefix(path, super::scalpel::DEFAULT_BINARY_MAX_BYTES)
        {
            if let Some(pdf_items) = extract_pdf_metadata(&data) {
                items.extend(pdf_items);
            }
        }
    }

    if ext == "docx" || ext == "xlsx" || ext == "pptx" {
        if let Ok(zip_items) = extract_office_metadata(path) {
            items.extend(zip_items);
        }
    }

    Ok(MetadataCollection {
        file_path: path_str,
        metadata_items: items,
    })
}

fn extract_basic_exif(data: &[u8]) -> Option<Vec<MetadataItem>> {
    if data.len() < 4 || data[0..2] != b"\xFF\xD8"[..] {
        return None;
    }

    let mut items = Vec::new();
    let mut offset = 2;

    while offset + 4 < data.len() {
        if data[offset] != 0xFF {
            offset += 1;
            continue;
        }

        let marker = data[offset + 1];

        if marker == 0xE1 {
            let _length = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            let exif_offset = offset + 4;

            if data.len() > exif_offset + 6 && data[exif_offset..exif_offset + 4] == b"Exif"[..] {
                items.push(MetadataItem {
                    name: "HasEXIF".to_string(),
                    value: "true".to_string(),
                    source: MetadataSource::EXIF,
                });
            }
            break;
        } else if marker == 0xD9 || marker == 0xD8 {
            break;
        } else if marker >= 0xC0 {
            let length = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            offset += length + 2;
        } else {
            offset += 2;
        }
    }

    Some(items)
}

fn extract_pdf_metadata(data: &[u8]) -> Option<Vec<MetadataItem>> {
    if data.len() < 8 || data[0..5] != b"%PDF-"[..] {
        return None;
    }

    let mut items = Vec::new();

    if let Ok(version) = String::from_utf8(data[5..10].to_vec()) {
        items.push(MetadataItem {
            name: "PDFVersion".to_string(),
            value: version,
            source: MetadataSource::PDF,
        });
    }

    let content = String::from_utf8_lossy(data);

    for line in content.lines() {
        if line.starts_with("/Title")
            || line.starts_with("/Author")
            || line.starts_with("/Subject")
            || line.starts_with("/Creator")
            || line.starts_with("/Producer")
            || line.starts_with("/CreationDate")
            || line.starts_with("/ModDate")
        {
            items.push(MetadataItem {
                name: line[1..10].trim().to_string(),
                value: line[11..].trim().to_string(),
                source: MetadataSource::PDF,
            });
        }
    }

    Some(items)
}

fn extract_office_metadata(path: &Path) -> Result<Vec<MetadataItem>, ForensicError> {
    let mut items = Vec::new();

    let file = std::io::Cursor::new(super::scalpel::read_prefix(
        path,
        super::scalpel::DEFAULT_BINARY_MAX_BYTES,
    )?);
    let archive = zip::ZipArchive::new(file);

    if let Ok(mut zip) = archive {
        if let Ok(mut doc_props) = zip.by_name("docProps/core.xml") {
            let mut content = String::new();
            doc_props.read_to_string(&mut content).ok();

            for line in content.lines() {
                if line.contains("dc:") || line.contains("cp:") {
                    if let Some(start) = line.find(">") {
                        if let Some(end) = line.rfind("<") {
                            let tag = line[1..start].replace("dc:", "").replace("cp:", "");
                            let value = line[start + 1..end].to_string();
                            if !value.is_empty() {
                                items.push(MetadataItem {
                                    name: tag,
                                    value,
                                    source: MetadataSource::Office,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(items)
}
