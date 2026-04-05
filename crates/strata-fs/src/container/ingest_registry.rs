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
            _ => {
                if is_numeric_split || is_r_split || is_alpha_split {
                    (ContainerType::SplitRaw, "container::split_raw".to_string())
                } else if path.is_dir() {
                    (ContainerType::Directory, "container::directory".to_string())
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
            ("ufed export folder", "partial", "ios::cellebrite"),
            ("graykey export folder", "partial", "ios::graykey"),
        ]
    }
}
