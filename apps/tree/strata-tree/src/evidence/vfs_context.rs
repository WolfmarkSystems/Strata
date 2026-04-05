//! VFS read context — unified read access for host and container-backed entries.

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Component, Path};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};

use crate::state::{EvidenceSource, FileEntry};

#[derive(Clone, Default)]
pub struct VfsReadContext {
    pub vfs_map: Arc<HashMap<String, Arc<dyn VfsReader + Send + Sync>>>,
}

pub trait VfsReader {
    fn read_file(&self, vfs_path: &str) -> Result<Vec<u8>>;
    fn read_range(&self, vfs_path: &str, offset: u64, len: usize) -> Result<Vec<u8>>;
    fn file_size(&self, vfs_path: &str) -> Result<u64>;
}

struct ContainerVfsReader {
    source_path: String,
    opened_source: Mutex<Option<strata_fs::container::EvidenceSource>>,
}

impl ContainerVfsReader {
    fn new(source_path: String) -> Self {
        Self {
            source_path,
            opened_source: Mutex::new(None),
        }
    }

    fn with_vfs<T>(
        &self,
        op: impl FnOnce(&dyn strata_fs::virtualization::VirtualFileSystem) -> Result<T>,
    ) -> Result<T> {
        let mut guard = self
            .opened_source
            .lock()
            .map_err(|_| anyhow!("source lock poisoned"))?;
        if guard.is_none() {
            let opened =
                strata_fs::container::open_evidence_container(Path::new(&self.source_path))
                    .map_err(|e| anyhow!("open evidence failed: {}", e))?;
            *guard = Some(opened);
        }
        let source = guard
            .as_ref()
            .ok_or_else(|| anyhow!("evidence source unavailable"))?;
        let vfs = source
            .vfs_ref()
            .ok_or_else(|| anyhow!("evidence has no virtual filesystem"))?;
        op(vfs)
    }
}

impl VfsReader for ContainerVfsReader {
    fn read_file(&self, vfs_path: &str) -> Result<Vec<u8>> {
        validate_vfs_virtual_path(vfs_path)?;
        self.with_vfs(|vfs| {
            vfs.open_file(Path::new(vfs_path))
                .map_err(|e| anyhow!("vfs read failed: {}", e))
        })
    }

    fn read_range(&self, vfs_path: &str, offset: u64, len: usize) -> Result<Vec<u8>> {
        if len == 0 {
            return Ok(Vec::new());
        }
        validate_vfs_virtual_path(vfs_path)?;
        self.with_vfs(|vfs| {
            vfs.read_file_range(Path::new(vfs_path), offset, len)
                .map_err(|e| anyhow!("vfs range read failed: {}", e))
        })
    }

    fn file_size(&self, vfs_path: &str) -> Result<u64> {
        validate_vfs_virtual_path(vfs_path)?;
        self.with_vfs(|vfs| {
            let meta = vfs
                .file_metadata(Path::new(vfs_path))
                .map_err(|e| anyhow!("vfs metadata failed: {}", e))?;
            Ok(meta.size)
        })
    }
}

impl VfsReadContext {
    pub fn new(vfs_map: Arc<HashMap<String, Arc<dyn VfsReader + Send + Sync>>>) -> Self {
        Self { vfs_map }
    }

    pub fn from_sources(sources: &[EvidenceSource]) -> Self {
        let mut vfs_map: HashMap<String, Arc<dyn VfsReader + Send + Sync>> = HashMap::new();
        for src in sources {
            if src.id.trim().is_empty() {
                continue;
            }
            vfs_map.insert(
                src.id.clone(),
                Arc::new(ContainerVfsReader::new(src.path.clone())),
            );
        }
        Self::new(Arc::new(vfs_map))
    }

    pub fn read_file(&self, entry: &FileEntry) -> Result<Vec<u8>> {
        if uses_host_path(entry) {
            return read_host_file(host_path_for_entry(entry))
                .map_err(|e| anyhow!("host read failed: {}", e));
        }

        let reader = self
            .vfs_map
            .get(&entry.evidence_id)
            .ok_or_else(|| anyhow!("missing VFS reader for evidence {}", entry.evidence_id))?;
        reader.read_file(&entry.vfs_path)
    }

    pub fn read_range(&self, entry: &FileEntry, offset: u64, len: usize) -> Result<Vec<u8>> {
        if len == 0 {
            return Ok(Vec::new());
        }

        if uses_host_path(entry) {
            return read_host_range(host_path_for_entry(entry), offset, len)
                .map_err(|e| anyhow!("host range read failed: {}", e));
        }

        let reader = self
            .vfs_map
            .get(&entry.evidence_id)
            .ok_or_else(|| anyhow!("missing VFS reader for evidence {}", entry.evidence_id))?;
        reader.read_range(&entry.vfs_path, offset, len)
    }

    pub fn file_size(&self, entry: &FileEntry) -> Result<u64> {
        if uses_host_path(entry) {
            return host_file_size(host_path_for_entry(entry))
                .map_err(|e| anyhow!("host size read failed: {}", e));
        }

        let reader = self
            .vfs_map
            .get(&entry.evidence_id)
            .ok_or_else(|| anyhow!("missing VFS reader for evidence {}", entry.evidence_id))?;
        reader.file_size(&entry.vfs_path)
    }
}

fn uses_host_path(entry: &FileEntry) -> bool {
    entry.evidence_id.trim().is_empty()
        || entry.vfs_path.is_empty()
        || (entry.is_carved && !entry.vfs_path.is_empty())
}

fn host_path_for_entry(entry: &FileEntry) -> &str {
    if entry.is_carved && !entry.vfs_path.is_empty() {
        return &entry.vfs_path;
    }
    &entry.path
}

fn read_host_file(path: &str) -> Result<Vec<u8>> {
    validate_host_path(path)?;
    std::fs::read(path).map_err(|e| anyhow!("host read failed: {}", e))
}

fn read_host_range(path: &str, offset: u64, len: usize) -> Result<Vec<u8>> {
    validate_host_path(path)?;
    let mut file = std::fs::File::open(path).map_err(|e| anyhow!("host open failed: {}", e))?;
    file.seek(SeekFrom::Start(offset))
        .map_err(|e| anyhow!("host seek failed: {}", e))?;
    let mut buf = vec![0u8; len];
    let read = file
        .read(&mut buf)
        .map_err(|e| anyhow!("host read failed: {}", e))?;
    buf.truncate(read);
    Ok(buf)
}

fn host_file_size(path: &str) -> Result<u64> {
    validate_host_path(path)?;
    let meta = std::fs::metadata(path).map_err(|e| anyhow!("host metadata failed: {}", e))?;
    Ok(meta.len())
}

fn validate_host_path(path: &str) -> Result<()> {
    if path.is_empty() {
        return Err(anyhow!("empty host path"));
    }
    if path.len() > 4096 {
        return Err(anyhow!("host path too long"));
    }
    if path.contains('\0') {
        return Err(anyhow!("host path contains null byte"));
    }
    Ok(())
}

fn validate_vfs_virtual_path(path: &str) -> Result<()> {
    if path.is_empty() {
        return Err(anyhow!("empty virtual path"));
    }
    if path.len() > 4096 {
        return Err(anyhow!("virtual path too long"));
    }
    if path.contains('\0') {
        return Err(anyhow!("virtual path contains null byte"));
    }

    let p = Path::new(path);
    for comp in p.components() {
        if matches!(comp, Component::ParentDir) {
            return Err(anyhow!("virtual path traversal is not allowed"));
        }
    }

    Ok(())
}
