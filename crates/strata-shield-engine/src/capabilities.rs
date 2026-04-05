use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CapabilityStatus {
    Production,
    Beta,
    Experimental,
    Stub,
    Unsupported,
}

impl std::fmt::Display for CapabilityStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CapabilityStatus::Production => write!(f, "Production"),
            CapabilityStatus::Beta => write!(f, "Beta"),
            CapabilityStatus::Experimental => write!(f, "Experimental"),
            CapabilityStatus::Stub => write!(f, "Stub"),
            CapabilityStatus::Unsupported => write!(f, "Unsupported"),
        }
    }
}

impl CapabilityStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            CapabilityStatus::Production => "Production",
            CapabilityStatus::Beta => "Beta",
            CapabilityStatus::Experimental => "Experimental",
            CapabilityStatus::Stub => "Stub",
            CapabilityStatus::Unsupported => "Unsupported",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capability {
    pub name: String,
    pub status: CapabilityStatus,
    pub description: String,
    pub limitations: Vec<String>,
    pub evidence_types: Vec<String>,
    pub platforms: Vec<String>,
    pub last_updated_utc: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilitiesReport {
    pub tool_version: String,
    pub generated_utc: String,
    pub capabilities: Vec<Capability>,
}

fn status_order(status: &CapabilityStatus) -> u8 {
    match status {
        CapabilityStatus::Production => 5,
        CapabilityStatus::Beta => 4,
        CapabilityStatus::Experimental => 3,
        CapabilityStatus::Stub => 2,
        CapabilityStatus::Unsupported => 1,
    }
}

pub fn get_capabilities_report() -> CapabilitiesReport {
    let mut capabilities = build_capabilities_registry();
    capabilities.sort_by(|a, b| a.name.cmp(&b.name));

    CapabilitiesReport {
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        generated_utc: chrono::Utc::now().to_rfc3339(),
        capabilities,
    }
}

fn build_capabilities_registry() -> Vec<Capability> {
    vec![
        // Containers
        Capability {
            name: "container.raw".to_string(),
            status: CapabilityStatus::Production,
            description: "Raw disk images (dd, raw)".to_string(),
            limitations: vec![],
            evidence_types: vec!["disk_image".to_string()],
            platforms: vec!["windows".to_string(), "macos".to_string(), "linux".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "container.e01".to_string(),
            status: CapabilityStatus::Production,
            description: "EnCase E01 format".to_string(),
            limitations: vec![],
            evidence_types: vec!["disk_image".to_string()],
            platforms: vec!["windows".to_string(), "macos".to_string(), "linux".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "container.aff4".to_string(),
            status: CapabilityStatus::Experimental,
            description: "AFF4 format".to_string(),
            limitations: vec!["Basic file enumeration implemented; full metadata and nested container support in progress".to_string()],
            evidence_types: vec!["disk_image".to_string()],
            platforms: vec!["windows".to_string(), "linux".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "container.vmdk".to_string(),
            status: CapabilityStatus::Experimental,
            description: "VMware VMDK virtual disk".to_string(),
            limitations: vec!["Container parsing implemented; VFS enumeration not yet available".to_string()],
            evidence_types: vec!["disk_image".to_string()],
            platforms: vec!["windows".to_string(), "linux".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "container.vhd".to_string(),
            status: CapabilityStatus::Experimental,
            description: "Microsoft VHD/VHDX virtual disk".to_string(),
            limitations: vec!["VHD container and VFS implemented; VHDX support partial".to_string()],
            evidence_types: vec!["disk_image".to_string()],
            platforms: vec!["windows".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "container.split".to_string(),
            status: CapabilityStatus::Stub,
            description: "Split/raw segments".to_string(),
            limitations: vec!["Not yet implemented".to_string()],
            evidence_types: vec!["disk_image".to_string()],
            platforms: vec!["windows".to_string(), "macos".to_string(), "linux".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },

        // Partition Schemes
        Capability {
            name: "partition.mbr".to_string(),
            status: CapabilityStatus::Production,
            description: "Master Boot Record".to_string(),
            limitations: vec![],
            evidence_types: vec!["volume".to_string()],
            platforms: vec!["windows".to_string(), "macos".to_string(), "linux".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "partition.gpt".to_string(),
            status: CapabilityStatus::Production,
            description: "GUID Partition Table".to_string(),
            limitations: vec![],
            evidence_types: vec!["volume".to_string()],
            platforms: vec!["windows".to_string(), "macos".to_string(), "linux".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "partition.raid".to_string(),
            status: CapabilityStatus::Experimental,
            description: "RAID detection".to_string(),
            limitations: vec!["RAID-0/1/5/6/10 detection only".to_string()],
            evidence_types: vec!["volume".to_string()],
            platforms: vec!["windows".to_string(), "linux".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },

        // Filesystems
        Capability {
            name: "filesystem.ntfs".to_string(),
            status: CapabilityStatus::Production,
            description: "NTFS filesystem".to_string(),
            limitations: vec![],
            evidence_types: vec!["volume".to_string()],
            platforms: vec!["windows".to_string(), "linux".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "filesystem.fat".to_string(),
            status: CapabilityStatus::Production,
            description: "FAT12/FAT16/FAT32 filesystem".to_string(),
            limitations: vec![],
            evidence_types: vec!["volume".to_string()],
            platforms: vec!["windows".to_string(), "macos".to_string(), "linux".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "filesystem.exfat".to_string(),
            status: CapabilityStatus::Production,
            description: "exFAT filesystem".to_string(),
            limitations: vec![],
            evidence_types: vec!["volume".to_string()],
            platforms: vec!["windows".to_string(), "macos".to_string(), "linux".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "filesystem.apfs".to_string(),
            status: CapabilityStatus::Beta,
            description: "Apple APFS filesystem".to_string(),
            limitations: vec!["Read-only; no snapshots yet".to_string(), "Encrypted volumes limited".to_string()],
            evidence_types: vec!["volume".to_string()],
            platforms: vec!["macos".to_string(), "linux".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "filesystem.ext4".to_string(),
            status: CapabilityStatus::Production,
            description: "ext4 filesystem".to_string(),
            limitations: vec![],
            evidence_types: vec!["volume".to_string()],
            platforms: vec!["linux".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "filesystem.hfsplus".to_string(),
            status: CapabilityStatus::Stub,
            description: "HFS+ filesystem".to_string(),
            limitations: vec!["Read-only support".to_string()],
            evidence_types: vec!["volume".to_string()],
            platforms: vec!["macos".to_string(), "linux".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "filesystem.xfs".to_string(),
            status: CapabilityStatus::Stub,
            description: "XFS filesystem".to_string(),
            limitations: vec!["Limited metadata parsing".to_string()],
            evidence_types: vec!["volume".to_string()],
            platforms: vec!["linux".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },

        // Unallocated Region Mapping
        Capability {
            name: "filesystem.ntfs.unallocated_map".to_string(),
            status: CapabilityStatus::Production,
            description: "NTFS unallocated region enumeration via $Bitmap".to_string(),
            limitations: vec![],
            evidence_types: vec!["volume".to_string()],
            platforms: vec!["windows".to_string(), "linux".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "filesystem.exfat.unallocated_map".to_string(),
            status: CapabilityStatus::Experimental,
            description: "exFAT unallocated region enumeration".to_string(),
            limitations: vec!["Bitmap parsing not fully implemented".to_string()],
            evidence_types: vec!["volume".to_string()],
            platforms: vec!["windows".to_string(), "linux".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "filesystem.fat.unallocated_map".to_string(),
            status: CapabilityStatus::Stub,
            description: "FAT unallocated region enumeration".to_string(),
            limitations: vec!["Not implemented".to_string()],
            evidence_types: vec!["volume".to_string()],
            platforms: vec!["windows".to_string(), "linux".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "filesystem.ext4.unallocated_map".to_string(),
            status: CapabilityStatus::Beta,
            description: "ext4 unallocated region enumeration via block bitmaps".to_string(),
            limitations: vec!["Best-effort implementation".to_string()],
            evidence_types: vec!["volume".to_string()],
            platforms: vec!["linux".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "filesystem.apfs.unallocated_map".to_string(),
            status: CapabilityStatus::Experimental,
            description: "APFS unallocated region enumeration".to_string(),
            limitations: vec!["Space manager analysis not implemented".to_string()],
            evidence_types: vec!["volume".to_string()],
            platforms: vec!["macos".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },

        // Analysis Modules
        Capability {
            name: "module.carving".to_string(),
            status: CapabilityStatus::Production,
            description: "Signature-based file carving".to_string(),
            limitations: vec!["Fragmented files limited".to_string()],
            evidence_types: vec!["disk_image".to_string(), "volume".to_string()],
            platforms: vec!["windows".to_string(), "macos".to_string(), "linux".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "module.timeline".to_string(),
            status: CapabilityStatus::Production,
            description: "Timeline generation and analysis".to_string(),
            limitations: vec![],
            evidence_types: vec!["disk_image".to_string(), "volume".to_string()],
            platforms: vec!["windows".to_string(), "macos".to_string(), "linux".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "module.classification".to_string(),
            status: CapabilityStatus::Beta,
            description: "File type classification and analysis".to_string(),
            limitations: vec![],
            evidence_types: vec!["disk_image".to_string(), "volume".to_string(), "file".to_string()],
            platforms: vec!["windows".to_string(), "macos".to_string(), "linux".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "module.preview".to_string(),
            status: CapabilityStatus::Beta,
            description: "File content preview".to_string(),
            limitations: vec!["Limited format support".to_string()],
            evidence_types: vec!["file".to_string()],
            platforms: vec!["windows".to_string(), "macos".to_string(), "linux".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },

        // Windows Artifacts
        Capability {
            name: "artifact.windows.registry".to_string(),
            status: CapabilityStatus::Production,
            description: "Windows Registry parsing".to_string(),
            limitations: vec![],
            evidence_types: vec!["disk_image".to_string(), "volume".to_string()],
            platforms: vec!["windows".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "artifact.windows.browser".to_string(),
            status: CapabilityStatus::Production,
            description: "Windows browser history extraction".to_string(),
            limitations: vec!["Chrome/Edge/Firefox supported".to_string()],
            evidence_types: vec!["disk_image".to_string(), "volume".to_string()],
            platforms: vec!["windows".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "artifact.windows.chat".to_string(),
            status: CapabilityStatus::Experimental,
            description: "Windows chat/ messaging app artifacts".to_string(),
            limitations: vec!["Telegram, Signal, WhatsApp support".to_string()],
            evidence_types: vec!["disk_image".to_string(), "volume".to_string()],
            platforms: vec!["windows".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "artifact.windows.registry.hive".to_string(),
            status: CapabilityStatus::Production,
            description: "Windows registry hive parsing (REGF/NK/value traversal)".to_string(),
            limitations: vec!["Best coverage for core hive layouts; malformed hives are best-effort".to_string()],
            evidence_types: vec!["disk_image".to_string(), "volume".to_string(), "file".to_string()],
            platforms: vec!["windows".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "artifact.windows.registry.exports".to_string(),
            status: CapabilityStatus::Production,
            description: "Windows .reg export parsing".to_string(),
            limitations: vec!["Depends on export completeness and encoding quality".to_string()],
            evidence_types: vec!["file".to_string()],
            platforms: vec!["windows".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "artifact.windows.eventlog".to_string(),
            status: CapabilityStatus::Production,
            description: "Windows EVTX/Event Log parsing".to_string(),
            limitations: vec!["Semantic mapping focuses on common security/investigative event families".to_string()],
            evidence_types: vec!["disk_image".to_string(), "volume".to_string(), "file".to_string()],
            platforms: vec!["windows".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "artifact.windows.eventlog.security".to_string(),
            status: CapabilityStatus::Production,
            description: "Windows Security log semantic extraction".to_string(),
            limitations: vec!["Coverage is strongest for common auth/process/group-change events".to_string()],
            evidence_types: vec!["disk_image".to_string(), "volume".to_string(), "file".to_string()],
            platforms: vec!["windows".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "artifact.windows.eventlog.sysmon".to_string(),
            status: CapabilityStatus::Production,
            description: "Sysmon event semantic extraction".to_string(),
            limitations: vec!["Coverage centers on high-value process/network/registry/file events".to_string()],
            evidence_types: vec!["disk_image".to_string(), "volume".to_string(), "file".to_string()],
            platforms: vec!["windows".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "artifact.windows.ntfs.mft".to_string(),
            status: CapabilityStatus::Production,
            description: "NTFS MFT record parsing".to_string(),
            limitations: vec!["Relies on readable MFT structures; severely damaged records are best-effort".to_string()],
            evidence_types: vec!["disk_image".to_string(), "volume".to_string()],
            platforms: vec!["windows".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "artifact.windows.ntfs.timeline".to_string(),
            status: CapabilityStatus::Beta,
            description: "NTFS-derived timeline signal extraction".to_string(),
            limitations: vec!["Timeline enrichment coverage varies by available filesystem metadata".to_string()],
            evidence_types: vec!["disk_image".to_string(), "volume".to_string()],
            platforms: vec!["windows".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "artifact.windows.prefetch".to_string(),
            status: CapabilityStatus::Production,
            description: "Windows Prefetch parsing".to_string(),
            limitations: vec!["Field richness depends on Prefetch format/version and data quality".to_string()],
            evidence_types: vec!["disk_image".to_string(), "volume".to_string(), "file".to_string()],
            platforms: vec!["windows".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "artifact.windows.jumplist".to_string(),
            status: CapabilityStatus::Production,
            description: "Windows Jump List parsing (DestList/entry extraction)".to_string(),
            limitations: vec!["Some app-specific/custom entry payloads remain best-effort".to_string()],
            evidence_types: vec!["disk_image".to_string(), "volume".to_string(), "file".to_string()],
            platforms: vec!["windows".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "artifact.windows.lnk".to_string(),
            status: CapabilityStatus::Beta,
            description: "Windows shortcut (LNK) parsing".to_string(),
            limitations: vec!["Advanced shell item edge-cases are still being expanded".to_string()],
            evidence_types: vec!["disk_image".to_string(), "volume".to_string(), "file".to_string()],
            platforms: vec!["windows".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "artifact.windows.shellbags".to_string(),
            status: CapabilityStatus::Beta,
            description: "Windows Shellbags parsing".to_string(),
            limitations: vec!["Complex shell item variants remain best-effort".to_string()],
            evidence_types: vec!["disk_image".to_string(), "volume".to_string(), "file".to_string()],
            platforms: vec!["windows".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "artifact.windows.userassist".to_string(),
            status: CapabilityStatus::Production,
            description: "Windows UserAssist extraction".to_string(),
            limitations: vec!["Depends on relevant user hive availability".to_string()],
            evidence_types: vec!["disk_image".to_string(), "volume".to_string(), "file".to_string()],
            platforms: vec!["windows".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "artifact.windows.bam".to_string(),
            status: CapabilityStatus::Production,
            description: "Windows BAM execution artifact extraction".to_string(),
            limitations: vec!["Coverage depends on SYSTEM hive and version-specific key layout".to_string()],
            evidence_types: vec!["disk_image".to_string(), "volume".to_string(), "file".to_string()],
            platforms: vec!["windows".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "artifact.windows.usb".to_string(),
            status: CapabilityStatus::Production,
            description: "Windows USB device history extraction".to_string(),
            limitations: vec!["Data completeness depends on registry/log retention".to_string()],
            evidence_types: vec!["disk_image".to_string(), "volume".to_string(), "file".to_string()],
            platforms: vec!["windows".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "artifact.windows.amcache".to_string(),
            status: CapabilityStatus::Beta,
            description: "Windows Amcache extraction".to_string(),
            limitations: vec!["Primarily export/record-driven in current implementation".to_string()],
            evidence_types: vec!["disk_image".to_string(), "volume".to_string(), "file".to_string()],
            platforms: vec!["windows".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "artifact.windows.autoruns".to_string(),
            status: CapabilityStatus::Production,
            description: "Windows autorun persistence extraction".to_string(),
            limitations: vec!["Focuses on common Run/Winlogon-style persistence locations".to_string()],
            evidence_types: vec!["disk_image".to_string(), "volume".to_string(), "file".to_string()],
            platforms: vec!["windows".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "artifact.windows.services".to_string(),
            status: CapabilityStatus::Beta,
            description: "Windows service configuration extraction".to_string(),
            limitations: vec!["Service metadata interpretation is still being expanded".to_string()],
            evidence_types: vec!["disk_image".to_string(), "volume".to_string(), "file".to_string()],
            platforms: vec!["windows".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "artifact.windows.scheduled_tasks".to_string(),
            status: CapabilityStatus::Beta,
            description: "Windows scheduled task extraction".to_string(),
            limitations: vec!["Some XML/action edge-cases remain best-effort".to_string()],
            evidence_types: vec!["disk_image".to_string(), "volume".to_string(), "file".to_string()],
            platforms: vec!["windows".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "artifact.windows.powershell".to_string(),
            status: CapabilityStatus::Beta,
            description: "Windows PowerShell artifact extraction".to_string(),
            limitations: vec!["Coverage depends on available logs/history/transcript artifacts".to_string()],
            evidence_types: vec!["disk_image".to_string(), "volume".to_string(), "file".to_string()],
            platforms: vec!["windows".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "artifact.windows.recycle_bin".to_string(),
            status: CapabilityStatus::Beta,
            description: "Windows Recycle Bin artifact extraction".to_string(),
            limitations: vec!["Coverage is strongest when $I/$R pairs are present".to_string()],
            evidence_types: vec!["disk_image".to_string(), "volume".to_string(), "file".to_string()],
            platforms: vec!["windows".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "artifact.windows.thumbcache".to_string(),
            status: CapabilityStatus::Experimental,
            description: "Windows thumbnail cache extraction".to_string(),
            limitations: vec!["Format/version edge-cases are still being expanded".to_string()],
            evidence_types: vec!["disk_image".to_string(), "volume".to_string(), "file".to_string()],
            platforms: vec!["windows".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "artifact.windows.rdp".to_string(),
            status: CapabilityStatus::Beta,
            description: "Windows RDP artifact extraction".to_string(),
            limitations: vec!["Coverage depends on host/user artifact availability".to_string()],
            evidence_types: vec!["disk_image".to_string(), "volume".to_string(), "file".to_string()],
            platforms: vec!["windows".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "artifact.windows.iis".to_string(),
            status: CapabilityStatus::Beta,
            description: "Windows IIS configuration/log parsing".to_string(),
            limitations: vec!["Schema/field coverage is focused on common IIS log formats".to_string()],
            evidence_types: vec!["disk_image".to_string(), "volume".to_string(), "file".to_string()],
            platforms: vec!["windows".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "artifact.windows.defender".to_string(),
            status: CapabilityStatus::Beta,
            description: "Windows Defender artifact extraction".to_string(),
            limitations: vec!["Event/configuration depth depends on available artifacts".to_string()],
            evidence_types: vec!["disk_image".to_string(), "volume".to_string(), "file".to_string()],
            platforms: vec!["windows".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "artifact.windows.wmi".to_string(),
            status: CapabilityStatus::Experimental,
            description: "Windows WMI artifact extraction".to_string(),
            limitations: vec!["Persistence and trace coverage is best-effort in current implementation".to_string()],
            evidence_types: vec!["disk_image".to_string(), "volume".to_string(), "file".to_string()],
            platforms: vec!["windows".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },

        // macOS Artifacts
        Capability {
            name: "artifact.macos.browser".to_string(),
            status: CapabilityStatus::Beta,
            description: "macOS browser history".to_string(),
            limitations: vec!["Safari, Chrome, Firefox".to_string()],
            evidence_types: vec!["disk_image".to_string(), "volume".to_string()],
            platforms: vec!["macos".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "artifact.macos.quarantine".to_string(),
            status: CapabilityStatus::Beta,
            description: "macOS LaunchServices quarantine event parsing".to_string(),
            limitations: vec![
                "Requires QuarantineEventsV2 SQLite artifact".to_string(),
                "Plist-heavy fallback coverage is available through macos-catalog best-effort parsing".to_string(),
            ],
            evidence_types: vec!["disk_image".to_string(), "volume".to_string(), "file".to_string()],
            platforms: vec!["macos".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "artifact.macos.shell_history".to_string(),
            status: CapabilityStatus::Beta,
            description: "macOS shell history (zsh/bash) parsing".to_string(),
            limitations: vec![
                "Parses plaintext shell history files only".to_string(),
                "No binary shell-session recovery in this parser".to_string(),
            ],
            evidence_types: vec!["disk_image".to_string(), "volume".to_string(), "file".to_string()],
            platforms: vec!["macos".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "artifact.macos.downloads".to_string(),
            status: CapabilityStatus::Beta,
            description: "macOS Safari download record parsing".to_string(),
            limitations: vec!["Depends on Safari History.db schema availability".to_string()],
            evidence_types: vec!["disk_image".to_string(), "volume".to_string(), "file".to_string()],
            platforms: vec!["macos".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "artifact.macos.catalog".to_string(),
            status: CapabilityStatus::Experimental,
            description: "Expanded macOS artifact catalog parser set".to_string(),
            limitations: vec![
                "Best-effort parser set; coverage varies by artifact source availability".to_string(),
                "Some entries are text-based collectors for exported artifacts".to_string(),
            ],
            evidence_types: vec!["disk_image".to_string(), "volume".to_string(), "file".to_string()],
            platforms: vec!["macos".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },

        // Workflows
        Capability {
            name: "workflow.verify".to_string(),
            status: CapabilityStatus::Production,
            description: "Case verification workflow".to_string(),
            limitations: vec![],
            evidence_types: vec!["disk_image".to_string()],
            platforms: vec!["windows".to_string(), "macos".to_string(), "linux".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "workflow.replay".to_string(),
            status: CapabilityStatus::Production,
            description: "Deterministic replay workflow".to_string(),
            limitations: vec![],
            evidence_types: vec!["disk_image".to_string()],
            platforms: vec!["windows".to_string(), "macos".to_string(), "linux".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "workflow.watchpoints".to_string(),
            status: CapabilityStatus::Production,
            description: "Integrity watchpoints".to_string(),
            limitations: vec![],
            evidence_types: vec!["disk_image".to_string()],
            platforms: vec!["windows".to_string(), "macos".to_string(), "linux".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "workflow.triage".to_string(),
            status: CapabilityStatus::Production,
            description: "Full triage session workflow".to_string(),
            limitations: vec![],
            evidence_types: vec!["disk_image".to_string()],
            platforms: vec!["windows".to_string(), "macos".to_string(), "linux".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "workflow.examiner-presets".to_string(),
            status: CapabilityStatus::Production,
            description: "Examiner presets for defensible workflow".to_string(),
            limitations: vec![],
            evidence_types: vec!["disk_image".to_string()],
            platforms: vec!["windows".to_string(), "macos".to_string(), "linux".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },

        // Mobile Artifacts
        Capability {
            name: "artifact.mobile.signal".to_string(),
            status: CapabilityStatus::Experimental,
            description: "Signal Android message database parsing".to_string(),
            limitations: vec![
                "Fixture-backed zero-row validation only; broader schema coverage still expanding".to_string(),
                "Message extraction focuses on SQLite-backed message tables and does not yet model groups or attachments deeply".to_string(),
            ],
            evidence_types: vec!["mobile_backup".to_string(), "file".to_string()],
            platforms: vec!["android".to_string()],
            last_updated_utc: "2026-03-27T00:00:00Z".to_string(),
        },
        Capability {
            name: "artifact.mobile.whatsapp".to_string(),
            status: CapabilityStatus::Experimental,
            description: "WhatsApp mobile message database parsing".to_string(),
            limitations: vec![
                "Fixture-backed zero-row validation only; schema and attachment coverage are still expanding".to_string(),
                "Parsing focuses on SQLite message tables and may return empty on unsupported app schema variants".to_string(),
            ],
            evidence_types: vec!["mobile_backup".to_string(), "file".to_string()],
            platforms: vec!["android".to_string(), "ios".to_string()],
            last_updated_utc: "2026-03-27T00:00:00Z".to_string(),
        },

        // Live Analysis        Capability {
            name: "live.memory".to_string(),
            status: CapabilityStatus::Experimental,
            description: "Live memory acquisition and analysis".to_string(),
            limitations: vec!["Windows only; limited volatility support".to_string()],
            evidence_types: vec!["memory".to_string()],
            platforms: vec!["windows".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "live.registry".to_string(),
            status: CapabilityStatus::Stub,
            description: "Live Windows Registry access".to_string(),
            limitations: vec!["Windows only; read-only".to_string()],
            evidence_types: vec!["live".to_string()],
            platforms: vec!["windows".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },

        // Encryption
        Capability {
            name: "encryption.bitlocker".to_string(),
            status: CapabilityStatus::Experimental,
            description: "BitLocker encrypted volume support".to_string(),
            limitations: vec!["Requires recovery password or TPM".to_string()],
            evidence_types: vec!["volume".to_string()],
            platforms: vec!["windows".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "encryption.luks".to_string(),
            status: CapabilityStatus::Stub,
            description: "Linux LUKS encrypted volume".to_string(),
            limitations: vec!["Requires passphrase".to_string()],
            evidence_types: vec!["volume".to_string()],
            platforms: vec!["linux".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "encryption.filevault".to_string(),
            status: CapabilityStatus::Stub,
            description: "macOS FileVault encrypted volume".to_string(),
            limitations: vec!["Requires recovery key".to_string()],
            evidence_types: vec!["volume".to_string()],
            platforms: vec!["macos".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },

        // Reporting
        Capability {
            name: "export.report".to_string(),
            status: CapabilityStatus::Production,
            description: "Report generation".to_string(),
            limitations: vec![],
            evidence_types: vec!["disk_image".to_string()],
            platforms: vec!["windows".to_string(), "macos".to_string(), "linux".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
        Capability {
            name: "export.defensibility".to_string(),
            status: CapabilityStatus::Production,
            description: "Defensibility bundle export".to_string(),
            limitations: vec![],
            evidence_types: vec!["disk_image".to_string()],
            platforms: vec!["windows".to_string(), "macos".to_string(), "linux".to_string()],
            last_updated_utc: "2024-01-01T00:00:00Z".to_string(),
        },
    ]
}

pub fn can_run(name: &str, minimum: CapabilityStatus) -> bool {
    let report = get_capabilities_report();

    for cap in &report.capabilities {
        if cap.name == name {
            return status_order(&cap.status) >= status_order(&minimum);
        }
    }

    false
}

pub fn require_capability(name: &str, minimum: CapabilityStatus) -> anyhow::Result<()> {
    if can_run(name, minimum) {
        Ok(())
    } else {
        let report = get_capabilities_report();

        let cap = report.capabilities.iter().find(|c| c.name == name);

        let (status, limitations) = match cap {
            Some(c) => (c.status.as_str().to_string(), c.limitations.clone()),
            None => (
                "Not registered".to_string(),
                vec!["Capability not found in registry".to_string()],
            ),
        };

        anyhow::bail!(
            "Capability unavailable: {} (required: {}, available: {}). Limitations: {:?}",
            name,
            minimum,
            status,
            limitations
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityCheck {
    pub name: String,
    pub requested_status: CapabilityStatus,
    pub available_status: CapabilityStatus,
    pub allowed: bool,
    pub limitations: Vec<String>,
}

pub fn check_capabilities(requirements: Vec<(&str, CapabilityStatus)>) -> Vec<CapabilityCheck> {
    let report = get_capabilities_report();
    let cap_map: HashMap<String, &Capability> = report
        .capabilities
        .iter()
        .map(|c| (c.name.clone(), c))
        .collect();

    requirements
        .iter()
        .map(|(name, requested)| {
            let available = *cap_map
                .get(*name)
                .map(|c| &c.status)
                .unwrap_or(&CapabilityStatus::Unsupported);
            let limitations = cap_map
                .get(*name)
                .map(|c| c.limitations.clone())
                .unwrap_or_default();

            CapabilityCheck {
                name: name.to_string(),
                requested_status: *requested,
                available_status: available,
                allowed: status_order(&available) >= status_order(requested),
                limitations,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_ordering() {
        assert!(
            status_order(&CapabilityStatus::Production) >= status_order(&CapabilityStatus::Beta)
        );
        assert!(
            status_order(&CapabilityStatus::Beta) >= status_order(&CapabilityStatus::Experimental)
        );
        assert!(
            status_order(&CapabilityStatus::Experimental) >= status_order(&CapabilityStatus::Stub)
        );
        assert!(
            status_order(&CapabilityStatus::Stub) >= status_order(&CapabilityStatus::Unsupported)
        );
    }

    #[test]
    fn test_can_run_production() {
        assert!(can_run("container.raw", CapabilityStatus::Production));
    }

    #[test]
    fn test_cannot_run_unsupported() {
        assert!(!can_run("filesystem.hfsplus", CapabilityStatus::Production));
    }

    #[test]
    fn test_capabilities_sorted() {
        let report = get_capabilities_report();
        let names: Vec<&str> = report
            .capabilities
            .iter()
            .map(|c| c.name.as_str())
            .collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
    }

    #[test]
    fn test_check_capabilities() {
        let results = check_capabilities(vec![
            ("container.raw", CapabilityStatus::Production),
            ("filesystem.hfsplus", CapabilityStatus::Beta),
        ]);

        assert_eq!(results.len(), 2);
        assert!(results[0].allowed);
        assert!(!results[1].allowed);
    }
}

