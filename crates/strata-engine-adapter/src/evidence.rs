//! Evidence loading + filesystem tree walking. Wires the strata-fs
//! `EvidenceSource` + `VirtualFileSystem` API into the adapter's clean types.

use crate::store::{
    drop_evidence, get_evidence, insert_evidence, CachedFile, CachedNode, OpenEvidence,
};
use crate::types::*;
use std::path::{Path, PathBuf};
use strata_fs::container::EvidenceSource;
use strata_fs::virtualization::{VfsEntry, VolumeInfo};

/// Open an evidence image and register it in the in-process store.
pub fn parse_evidence(path: &str) -> AdapterResult<EvidenceInfo> {
    let p = Path::new(path);
    if !p.exists() {
        return Err(AdapterError::EvidenceNotFound(path.to_string()));
    }

    let source = EvidenceSource::open(p)
        .map_err(|e| AdapterError::EngineError(format!("EvidenceSource::open: {e}")))?;

    let id = format!("ev-{:x}", short_hash(path));
    let name = p
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string());
    let size_bytes = source.size;
    let format = source.container_type.as_str().to_string();

    // Build root nodes (evidence + each volume) up front so the UI tree opens
    // immediately.
    let mut root_node_ids = Vec::new();
    let mut nodes: std::collections::HashMap<String, CachedNode> =
        std::collections::HashMap::new();

    // Top "evidence" node
    let evidence_node_id = "node-root".to_string();
    let evidence_node = CachedNode {
        id: evidence_node_id.clone(),
        name: format!("{} ({})", name, format_size(size_bytes)),
        node_type: "evidence".to_string(),
        vfs_path: PathBuf::from("/"),
        volume_index: None,
        parent_id: None,
        depth: 0,
        child_ids: Vec::new(),
        children_loaded: true, // children = volumes, populated below
    };
    nodes.insert(evidence_node_id.clone(), evidence_node);
    root_node_ids.push(evidence_node_id.clone());

    let mut total_files: u64 = 0;
    let mut volume_child_ids: Vec<String> = Vec::new();

    if let Some(vfs) = source.vfs.as_ref() {
        let volumes = vfs.get_volumes();

        if volumes.is_empty() {
            // Plain directory or single-volume image with no partition table
            // — synthesize a single "root" volume node so the user can drill
            // into the FS root.
            let vol_id = format!("{}-vol-0", evidence_node_id);
            let vol_node = CachedNode {
                id: vol_id.clone(),
                name: format!("[{}]", source.container_type.as_str()),
                node_type: "volume".to_string(),
                vfs_path: vfs.root().clone(),
                volume_index: None,
                parent_id: Some(evidence_node_id.clone()),
                depth: 1,
                child_ids: Vec::new(),
                children_loaded: false,
            };
            nodes.insert(vol_id.clone(), vol_node);
            volume_child_ids.push(vol_id);
        } else {
            for v in &volumes {
                let vol_id = format!("{}-vol-{}", evidence_node_id, v.volume_index);
                let label = volume_label(v);
                let node = CachedNode {
                    id: vol_id.clone(),
                    name: label,
                    node_type: "volume".to_string(),
                    vfs_path: PathBuf::from(format!("/ntfs_vol{}", v.volume_index)),
                    volume_index: Some(v.volume_index),
                    parent_id: Some(evidence_node_id.clone()),
                    depth: 1,
                    child_ids: Vec::new(),
                    children_loaded: false,
                };
                nodes.insert(vol_id.clone(), node);
                volume_child_ids.push(vol_id);
                total_files += estimate_volume_files(v);
            }
        }
    }

    // Wire up evidence-node children
    if let Some(ev) = nodes.get_mut(&evidence_node_id) {
        ev.child_ids = volume_child_ids.clone();
    }

    // Stash in store
    let arc = insert_evidence(id.clone(), source);
    {
        let mut guard = arc.lock().expect("evidence lock poisoned");
        guard.nodes = nodes;
        guard.root_node_ids = root_node_ids;
    }

    Ok(EvidenceInfo {
        id,
        path: path.to_string(),
        name,
        size_bytes,
        size_display: format_size(size_bytes),
        format,
        file_count: total_files,
        hash_md5: None,
        hash_sha1: None,
    })
}

/// Aggregate stats across the cached files of an evidence. Stats grow over
/// time as the user expands directory nodes (lazy walks populate the cache).
pub fn get_stats(evidence_id: &str) -> AdapterResult<EngineStats> {
    let arc = get_evidence(evidence_id)?;
    let guard = arc.lock().expect("evidence lock poisoned");

    let files = guard.files.len() as u64;
    let suspicious = guard.files.values().filter(|f| is_suspicious(f)).count() as u64;
    let flagged = guard.files.values().filter(|f| is_flagged(f)).count() as u64;
    let hashed = crate::hashing::hashed_count(evidence_id);
    let carved = 0; // populated by Remnant plugin in v0.5.0
    let artifacts = crate::plugins::cached_artifact_count(evidence_id);

    Ok(EngineStats {
        files,
        suspicious,
        flagged,
        carved,
        hashed,
        artifacts,
    })
}

fn is_suspicious(f: &crate::store::CachedFile) -> bool {
    const MARKERS: &[&str] = &["mimikatz", "lsass", "cleanup.ps1", "psexec", "nc.exe"];
    let lc = f.name.to_lowercase();
    MARKERS.iter().any(|m| lc.contains(m))
}

fn is_flagged(f: &crate::store::CachedFile) -> bool {
    let lc = f.name.to_lowercase();
    lc == "mimikatz.exe" || lc == "lsass.dmp"
}

/// Close an opened evidence (drops its VFS).
pub fn close_evidence(evidence_id: &str) -> AdapterResult<()> {
    if drop_evidence(evidence_id) {
        Ok(())
    } else {
        Err(AdapterError::EvidenceNotFound(evidence_id.to_string()))
    }
}

/// Return the top-level tree node(s) for an evidence — typically a single
/// "evidence" root that contains the volumes as children.
pub fn get_tree_root(evidence_id: &str) -> AdapterResult<Vec<TreeNode>> {
    let arc = get_evidence(evidence_id)?;
    let guard = arc.lock().expect("evidence lock poisoned");
    let mut out = Vec::new();
    for id in &guard.root_node_ids {
        if let Some(node) = guard.nodes.get(id) {
            out.push(to_tree_node(node));
        }
    }
    Ok(out)
}

/// Return the children of a tree node, lazily walking the underlying VFS the
/// first time the node is expanded.
pub fn get_tree_children(evidence_id: &str, node_id: &str) -> AdapterResult<Vec<TreeNode>> {
    let arc = get_evidence(evidence_id)?;
    // First read existing children — if cached, return immediately.
    {
        let guard = arc.lock().expect("evidence lock poisoned");
        if let Some(node) = guard.nodes.get(node_id) {
            if node.children_loaded {
                return Ok(node
                    .child_ids
                    .iter()
                    .filter_map(|cid| guard.nodes.get(cid).map(to_tree_node))
                    .collect());
            }
        } else {
            return Err(AdapterError::ParseError(format!(
                "tree node {} not found",
                node_id
            )));
        }
    }

    // Need to walk: take a write-lock and populate.
    let mut guard = arc.lock().expect("evidence lock poisoned");
    let (vfs_path, depth, vol_index) = {
        let n = guard
            .nodes
            .get(node_id)
            .ok_or_else(|| AdapterError::ParseError(node_id.to_string()))?;
        (n.vfs_path.clone(), n.depth, n.volume_index)
    };

    let entries = walk_directory(&guard, &vfs_path, vol_index)?;

    let mut new_child_ids = Vec::new();
    for entry in entries {
        let child_id = format!("{}-{}", node_id, sanitize(&entry.name));
        let cached = CachedNode {
            id: child_id.clone(),
            name: entry.name.clone(),
            node_type: if entry.is_dir { "folder" } else { "file" }.to_string(),
            vfs_path: entry.path.clone(),
            volume_index: vol_index,
            parent_id: Some(node_id.to_string()),
            depth: depth + 1,
            child_ids: Vec::new(),
            children_loaded: false,
        };
        if entry.is_dir {
            guard.nodes.insert(child_id.clone(), cached);
            new_child_ids.push(child_id);
        } else {
            // For files, we record them in the file map so list_files can find
            // them later — but we still emit the tree node so a directory tree
            // can mix files and folders if the UI ever wants to.
            let file_id = format!("file-{}", short_hash(&entry.path.to_string_lossy()));
            let cached_file = CachedFile {
                id: file_id.clone(),
                vfs_path: entry.path.clone(),
                name: entry.name.clone(),
                extension: entry
                    .path
                    .extension()
                    .map(|e| e.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                size: entry.size,
                modified: entry
                    .modified
                    .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
                    .unwrap_or_else(|| "\u{2014}".to_string()),
                created: "\u{2014}".to_string(),
                accessed: "\u{2014}".to_string(),
                is_dir: false,
                parent_node_id: node_id.to_string(),
                mft_entry: None,
                inode: None,
            };
            guard.files.insert(file_id, cached_file);
        }
    }

    if let Some(node) = guard.nodes.get_mut(node_id) {
        node.child_ids = new_child_ids;
        node.children_loaded = true;
    }

    let result: Vec<TreeNode> = guard
        .nodes
        .get(node_id)
        .map(|n| n.child_ids.clone())
        .unwrap_or_default()
        .iter()
        .filter_map(|cid| guard.nodes.get(cid).map(to_tree_node))
        .collect();
    Ok(result)
}

/// Return the file listing for a tree node — only files (not subdirectories).
/// If the directory hasn't been walked yet, this triggers a walk.
pub fn get_files(
    evidence_id: &str,
    node_id: &str,
    filter: Option<&str>,
) -> AdapterResult<Vec<FileEntry>> {
    // Trigger a walk if the node hasn't been expanded yet.
    let _ = get_tree_children(evidence_id, node_id)?;

    let arc = get_evidence(evidence_id)?;
    let guard = arc.lock().expect("evidence lock poisoned");

    let filter_lc = filter.map(|f| f.to_lowercase());

    let mut out: Vec<FileEntry> = guard
        .files
        .values()
        .filter(|f| f.parent_node_id == node_id)
        .filter(|f| {
            filter_lc
                .as_ref()
                .map(|q| f.name.to_lowercase().contains(q))
                .unwrap_or(true)
        })
        .map(to_file_entry)
        .collect();

    out.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    Ok(out)
}

// ────────────────────────────────────────────────────────────────────────────
// Internals
// ────────────────────────────────────────────────────────────────────────────

fn walk_directory(
    open: &OpenEvidence,
    path: &Path,
    _vol_index: Option<usize>,
) -> AdapterResult<Vec<VfsEntry>> {
    let vfs = open
        .source
        .vfs
        .as_ref()
        .ok_or_else(|| AdapterError::EngineError("evidence has no VFS".to_string()))?;

    vfs.read_dir(path)
        .map_err(|e| AdapterError::EngineError(format!("read_dir({:?}): {e}", path)))
}

fn volume_label(v: &VolumeInfo) -> String {
    let fs = v.filesystem.as_str();
    let label = v.label.clone().unwrap_or_else(|| format!("Volume {}", v.volume_index));
    format!("[{} {}]", fs, label)
}

fn estimate_volume_files(_v: &VolumeInfo) -> u64 {
    // We can't cheaply count files without walking the whole MFT — return 0
    // here and let the UI show "—" until a directory is expanded.
    0
}

fn to_tree_node(n: &CachedNode) -> TreeNode {
    TreeNode {
        id: n.id.clone(),
        name: n.name.clone(),
        node_type: n.node_type.clone(),
        count: n.child_ids.len() as u64,
        has_children: !n.child_ids.is_empty() || !n.children_loaded,
        parent_id: n.parent_id.clone(),
        depth: n.depth,
        is_deleted: false,
        is_flagged: false,
        is_suspicious: false,
    }
}

fn to_file_entry(f: &CachedFile) -> FileEntry {
    FileEntry {
        id: f.id.clone(),
        name: f.name.clone(),
        extension: f.extension.clone(),
        size: f.size,
        size_display: format_size(f.size),
        modified: f.modified.clone(),
        created: f.created.clone(),
        accessed: f.accessed.clone(),
        full_path: f.vfs_path.to_string_lossy().into_owned(),
        sha256: None,
        md5: None,
        is_deleted: false,
        is_suspicious: false,
        is_flagged: false,
        category: classify(&f.extension),
        inode: f.inode,
        mft_entry: f.mft_entry,
    }
}

fn classify(ext: &str) -> String {
    match ext.to_lowercase().as_str() {
        "exe" | "dll" | "sys" => "Executable".to_string(),
        "evtx" => "Event Log".to_string(),
        "dat" => "Registry Hive".to_string(),
        "log" => "System Log".to_string(),
        "ps1" => "PowerShell Script".to_string(),
        "lnk" => "Shell Link".to_string(),
        "zip" | "rar" | "7z" => "Archive".to_string(),
        "pdf" => "PDF Document".to_string(),
        "" => "File".to_string(),
        _ => "File".to_string(),
    }
}

/// Cheap stable hash for generating ids — not cryptographic, just unique-enough.
pub fn short_hash(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    h
}

fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect::<String>()
        .chars()
        .take(32)
        .collect()
}
