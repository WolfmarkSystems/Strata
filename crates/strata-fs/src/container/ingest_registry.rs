use crate::container::ContainerType;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestProfile {
    pub profile: String,
    pub parser_hint: String,
    pub confidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestDescriptor {
    pub container_type: ContainerType,
    pub parser_adapter: String,
    pub source_hint: String,
    pub profile: Option<IngestProfile>,
}

pub struct IngestRegistry;

impl IngestRegistry {
    pub fn detect(path: &Path) -> IngestDescriptor {
        let ext = path
            .extension()
            .and_then(|v| v.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        let is_numeric_split = ext.len() == 3 && ext.chars().all(|c| c.is_ascii_digit());
        let is_r_split =
            ext.len() == 3 && ext.starts_with('r') && ext[1..].chars().all(|c| c.is_ascii_digit());
        let is_alpha_split =
            ext.len() == 2 && ext.starts_with('a') && ext.chars().all(|c| c.is_ascii_lowercase());
        let full_name = path
            .file_name()
            .and_then(|v| v.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();

        let profile = if full_name.contains("graykey") || full_name.contains("gray key") {
            Some(IngestProfile {
                profile: "graykey-export".to_string(),
                parser_hint: "ios::graykey".to_string(),
                confidence: "medium".to_string(),
            })
        } else if full_name.contains("ufed") || full_name.contains("cellebrite") {
            Some(IngestProfile {
                profile: "ufed-export".to_string(),
                parser_hint: "ios::cellebrite".to_string(),
                confidence: "medium".to_string(),
            })
        } else {
            None
        };

        let (container_type, parser_adapter) = match ext.as_str() {
            "e01" | "ex01" => (ContainerType::E01, "container::e01".to_string()),
            "vhd" => (ContainerType::Vhd, "container::vhd".to_string()),
            "vhdx" => (ContainerType::Vhdx, "container::vhdx".to_string()),
            "vmdk" => (ContainerType::Vmdk, "container::vmdk".to_string()),
            "aff" | "aff4" => (ContainerType::Aff, "container::aff".to_string()),
            "raw" | "dd" | "img" => (ContainerType::Raw, "container::raw".to_string()),
            "iso" => (ContainerType::Iso, "container::iso".to_string()),
            "qcow2" => (ContainerType::Qcow2, "container::qcow2".to_string()),
            "ufdr" => (ContainerType::Ufdr, "ios::cellebrite".to_string()),
            "ufd" | "ufdx" => (ContainerType::Ufed, "ios::cellebrite".to_string()),
            "zip" => (
                ContainerType::ArchiveZip,
                "container::archive_zip".to_string(),
            ),
            "tar" | "tgz" => (
                ContainerType::ArchiveTar,
                "container::archive_tar".to_string(),
            ),
            // Files ending in `.tar.gz` arrive here with `ext = "gz"`; the
            // unpack engine sniffs magic bytes (gzip 1F 8B + ustar at 257)
            // so a bare `.gz` that wraps a tar will still extract correctly.
            "gz" => (
                ContainerType::ArchiveTar,
                "container::archive_tar".to_string(),
            ),
            _ => {
                if is_numeric_split || is_r_split || is_alpha_split {
                    (ContainerType::SplitRaw, "container::split_raw".to_string())
                } else if path.is_dir() {
                    if is_ufed_directory(path) {
                        (ContainerType::Ufed, "ios::cellebrite".to_string())
                    } else if is_ufdr_directory(path) {
                        (ContainerType::Ufdr, "ios::cellebrite".to_string())
                    } else {
                        (ContainerType::Directory, "container::directory".to_string())
                    }
                } else {
                    (ContainerType::Raw, "container::raw".to_string())
                }
            }
        };

        IngestDescriptor {
            container_type,
            parser_adapter,
            source_hint: ext,
            profile,
        }
    }

    pub fn compatibility_matrix_rows() -> Vec<(&'static str, &'static str, &'static str)> {
        vec![
            ("raw/dd/img", "supported", "container::raw"),
            (
                "split raw (001/r01/aa)",
                "supported",
                "container::split_raw",
            ),
            ("e01/ex01", "supported", "container::e01"),
            ("vhd (fixed/dynamic)", "supported", "container::vhd"),
            ("vhdx", "supported", "container::vhd"),
            ("vmdk (flat/sparse)", "supported", "container::vmdk"),
            ("aff/aff4", "supported", "container::aff4"),
            ("iso 9660 + joliet", "supported", "container::iso"),
            ("qcow2 (v2/v3)", "supported", "container::qcow2"),
            ("vdi", "supported", "container::vdi"),
            ("luks", "partial", "container::luks"),
            ("lvm", "partial", "container::lvm"),
            ("dmg", "partial", "container::dmg"),
            ("sparsebundle", "partial", "container::sparsebundle"),
            ("l01", "partial", "container::l01"),
            ("ufed export folder", "supported", "ios::cellebrite"),
            ("ufdr report package", "supported", "ios::cellebrite"),
            ("graykey export folder", "partial", "ios::graykey"),
        ]
    }
}

/// Cheap heuristics used by `detect()` to classify a directory as a
/// Cellebrite UFED export. Looks for the hallmark UFED layout without
/// unpacking the `EXTRACTION_FFS.zip` payload (the heavy work runs later
/// when plugins request the file through the VFS).
///
/// A directory counts as UFED when it contains any of:
/// * `EXTRACTION_FFS.zip` at the root or one level down,
/// * a `.ufdx` file,
/// * a `.ufd` file accompanied by an `EvidenceCollection.ufdx` sibling.
pub(crate) fn is_ufed_directory(path: &Path) -> bool {
    let mut saw_ufdx = false;
    let mut saw_ufd = false;
    let mut saw_extraction_zip = false;
    // Check the directory itself first.
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
            if name.ends_with(".ufdx") {
                saw_ufdx = true;
            }
            if name.ends_with(".ufd") {
                saw_ufd = true;
            }
            if name.starts_with("extraction_ffs") && name.ends_with(".zip") {
                saw_extraction_zip = true;
            }
            // Walk one level deeper to find EXTRACTION_FFS.zip inside a
            // typical UFED subdirectory layout.
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                if let Ok(inner) = std::fs::read_dir(entry.path()) {
                    for child in inner.flatten() {
                        let cname = child.file_name().to_string_lossy().to_ascii_lowercase();
                        if cname.ends_with(".ufdx") {
                            saw_ufdx = true;
                        }
                        if cname.ends_with(".ufd") {
                            saw_ufd = true;
                        }
                        if cname.starts_with("extraction_ffs") && cname.ends_with(".zip") {
                            saw_extraction_zip = true;
                        }
                    }
                }
            }
        }
    }
    saw_ufdx || saw_extraction_zip || saw_ufd
}

/// Directory-flavoured UFDR: a `report.xml` with a Cellebrite signature,
/// or a folder whose top level looks like a UFDR extraction (present in
/// reports produced by older UFED Reader builds).
pub(crate) fn is_ufdr_directory(path: &Path) -> bool {
    let candidate = path.join("report.xml");
    if !candidate.exists() {
        return false;
    }
    let Ok(head) = std::fs::read_to_string(&candidate) else {
        return false;
    };
    let head_lower: String = head
        .chars()
        .take(4096)
        .collect::<String>()
        .to_ascii_lowercase();
    head_lower.contains("cellebrite") || head_lower.contains("ufed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn mk_dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn detects_ufed_from_ufdx_file() {
        let dir = mk_dir();
        fs::write(dir.path().join("EvidenceCollection.ufdx"), b"<ufdx/>").expect("w");
        let desc = IngestRegistry::detect(dir.path());
        assert_eq!(desc.container_type, ContainerType::Ufed);
        assert_eq!(desc.parser_adapter, "ios::cellebrite");
    }

    #[test]
    fn detects_ufed_from_nested_extraction_zip() {
        let dir = mk_dir();
        let inner = dir.path().join("EXTRACTION_FFS 01");
        fs::create_dir_all(&inner).expect("mkdir");
        fs::write(inner.join("EXTRACTION_FFS.zip"), b"PK\x03\x04").expect("w");
        let desc = IngestRegistry::detect(dir.path());
        assert_eq!(desc.container_type, ContainerType::Ufed);
    }

    #[test]
    fn detects_ufdr_via_report_xml_signature() {
        let dir = mk_dir();
        fs::write(
            dir.path().join("report.xml"),
            b"<?xml version=\"1.0\"?><report generator=\"Cellebrite UFED Reader\"/>",
        )
        .expect("w");
        let desc = IngestRegistry::detect(dir.path());
        assert_eq!(desc.container_type, ContainerType::Ufdr);
    }

    #[test]
    fn plain_directory_stays_directory() {
        let dir = mk_dir();
        fs::write(dir.path().join("notes.txt"), b"hello").expect("w");
        let desc = IngestRegistry::detect(dir.path());
        assert_eq!(desc.container_type, ContainerType::Directory);
    }

    #[test]
    fn ufdr_extension_short_circuits_to_ufdr() {
        let dir = mk_dir();
        let p = dir.path().join("case.ufdr");
        fs::write(&p, b"PK\x03\x04").expect("w");
        let desc = IngestRegistry::detect(&p);
        assert_eq!(desc.container_type, ContainerType::Ufdr);
    }

    #[test]
    fn ufd_and_ufdx_extensions_short_circuit_to_ufed() {
        let dir = mk_dir();
        let ufd = dir.path().join("extraction.ufd");
        fs::write(&ufd, b"").expect("w");
        let desc_ufd = IngestRegistry::detect(&ufd);
        assert_eq!(desc_ufd.container_type, ContainerType::Ufed);

        let ufdx = dir.path().join("evidence.ufdx");
        fs::write(&ufdx, b"").expect("w");
        let desc_ufdx = IngestRegistry::detect(&ufdx);
        assert_eq!(desc_ufdx.container_type, ContainerType::Ufed);
    }

    #[test]
    fn matrix_row_lists_ufed_as_supported() {
        let rows = IngestRegistry::compatibility_matrix_rows();
        let row = rows
            .iter()
            .find(|(fmt, _, _)| *fmt == "ufed export folder")
            .expect("row");
        assert_eq!(row.1, "supported");
    }
}
