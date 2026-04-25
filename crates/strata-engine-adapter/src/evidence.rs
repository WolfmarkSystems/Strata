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

/// Sprint-11 P2 — return the node + breadcrumb chain that leads to a
/// source path so the UI can expand the evidence tree to that file.
///
/// Lookup strategy:
///   1. If a tree node already exists with `vfs_path == path`,
///      return it + its parent chain (cheap fast-path; common when
///      the user has already browsed near the target).
///   2. Otherwise, walk from each root volume node, eagerly expanding
///      `get_tree_children` along the path components until either
///      the target node is realised or a component is missing.
///
/// Returns `Err(AdapterError::NotFound)` rather than panicking when
/// the path isn't part of the evidence — examiners then see a clear
/// "source not found in evidence tree" toast.
pub fn navigate_to_path(
    evidence_id: &str,
    file_path: &str,
) -> AdapterResult<NavigationTarget> {
    use std::path::PathBuf;

    let target_path = PathBuf::from(file_path);

    // Fast path: check the cache directly. Tree nodes store paths in
    // a mix of forms — volume nodes carry the absolute VFS root,
    // child nodes hold the path relative to that root (FsVfs strips
    // the prefix when emitting VfsEntries). We accept both shapes.
    {
        let arc = get_evidence(evidence_id)?;
        let guard = arc.lock().expect("evidence lock poisoned");
        if let Some((id, _)) = guard
            .nodes
            .iter()
            .find(|(_, n)| paths_match_node(&target_path, n, &guard))
        {
            let breadcrumb = build_breadcrumb(&guard, id);
            return Ok(NavigationTarget {
                node_id: id.clone(),
                breadcrumb,
                file_id: None,
            });
        }
        if let Some((fid, _)) = guard
            .files
            .iter()
            .find(|(_, f)| paths_match_file(&target_path, f, &guard))
        {
            let parent = guard
                .files
                .get(fid)
                .and_then(|f| guard.nodes.get(&f.parent_node_id))
                .map(|n| n.id.clone());
            if let Some(parent_id) = parent {
                let breadcrumb = build_breadcrumb(&guard, &parent_id);
                return Ok(NavigationTarget {
                    node_id: parent_id,
                    breadcrumb,
                    file_id: Some(fid.clone()),
                });
            }
        }
    }

    // Slow path: walk from each root and force expansion until we
    // realise the target. Bail at MAX_TREE_DEPTH so a corrupt path
    // can't loop us.
    let root_ids: Vec<String> = {
        let arc = get_evidence(evidence_id)?;
        let guard = arc.lock().expect("evidence lock poisoned");
        guard.root_node_ids.clone()
    };
    for root in root_ids {
        // Force expansion of root → volume → ... using get_tree_children.
        if let Ok(target) = walk_to_path(evidence_id, &root, &target_path) {
            return Ok(target);
        }
    }
    Err(AdapterError::NotFound(format!(
        "source path not found in evidence tree: {file_path}"
    )))
}

fn walk_to_path(
    evidence_id: &str,
    start: &str,
    target: &Path,
) -> AdapterResult<NavigationTarget> {
    let mut current = start.to_string();
    for _ in 0..MAX_TREE_DEPTH {
        // Force-expand the current node.
        let _ = get_tree_children(evidence_id, &current)?;
        // Re-check the cache after expansion.
        let arc = get_evidence(evidence_id)?;
        let guard = arc.lock().expect("evidence lock poisoned");
        if let Some((id, _)) = guard
            .nodes
            .iter()
            .find(|(_, n)| paths_match_node(target, n, &guard))
        {
            let breadcrumb = build_breadcrumb(&guard, id);
            return Ok(NavigationTarget {
                node_id: id.clone(),
                breadcrumb,
                file_id: None,
            });
        }
        if let Some((fid, _)) = guard
            .files
            .iter()
            .find(|(_, f)| paths_match_file(target, f, &guard))
        {
            let parent = guard
                .files
                .get(fid)
                .and_then(|f| guard.nodes.get(&f.parent_node_id))
                .map(|n| n.id.clone());
            if let Some(parent_id) = parent {
                let breadcrumb = build_breadcrumb(&guard, &parent_id);
                return Ok(NavigationTarget {
                    node_id: parent_id,
                    breadcrumb,
                    file_id: Some(fid.clone()),
                });
            }
        }
        // Not found yet — pick the child node whose vfs_path is a
        // prefix of the target and recurse into it. If none match the
        // target isn't beneath this subtree.
        let next = guard
            .nodes
            .get(&current)
            .map(|n| n.child_ids.clone())
            .unwrap_or_default()
            .into_iter()
            .find(|cid| {
                guard
                    .nodes
                    .get(cid)
                    .map(|c| node_is_ancestor_of(target, c, &guard))
                    .unwrap_or(false)
            });
        match next {
            Some(c) => current = c,
            None => break,
        }
    }
    Err(AdapterError::NotFound(format!(
        "source path not found beneath {start}: {target:?}"
    )))
}

/// Resolve a tree node's `vfs_path` to an absolute filesystem path
/// for comparison. Volume nodes already hold an absolute root; child
/// nodes hold a path relative to that root and need it prefixed.
fn absolute_node_path(node: &CachedNode, open: &OpenEvidence) -> PathBuf {
    if node.vfs_path.is_absolute() {
        return node.vfs_path.clone();
    }
    if let Some(vfs) = open.source.vfs.as_ref() {
        return vfs.root().join(&node.vfs_path);
    }
    node.vfs_path.clone()
}

fn paths_match_node(target: &Path, node: &CachedNode, open: &OpenEvidence) -> bool {
    if node.vfs_path == target {
        return true;
    }
    absolute_node_path(node, open) == target
}

fn paths_match_file(
    target: &Path,
    file: &crate::store::CachedFile,
    open: &OpenEvidence,
) -> bool {
    if file.vfs_path == target {
        return true;
    }
    if file.vfs_path.is_absolute() {
        return false;
    }
    if let Some(vfs) = open.source.vfs.as_ref() {
        return vfs.root().join(&file.vfs_path) == target;
    }
    false
}

fn node_is_ancestor_of(target: &Path, node: &CachedNode, open: &OpenEvidence) -> bool {
    let abs = absolute_node_path(node, open);
    target.starts_with(&abs)
}

fn build_breadcrumb(open: &OpenEvidence, leaf: &str) -> Vec<String> {
    let mut chain = Vec::new();
    let mut cursor = Some(leaf.to_string());
    while let Some(id) = cursor {
        chain.push(id.clone());
        cursor = open
            .nodes
            .get(&id)
            .and_then(|n| n.parent_id.clone());
    }
    chain.reverse();
    chain
}

/// Sprint-11 P2 — return shape for `navigate_to_path`. The frontend
/// expands each id in `breadcrumb` (root → leaf), selects `node_id`,
/// and additionally highlights `file_id` when set.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct NavigationTarget {
    pub node_id: String,
    pub breadcrumb: Vec<String>,
    pub file_id: Option<String>,
}

/// Sprint-10 P4 — defense-in-depth recursion guard.
///
/// 50 levels is far deeper than any real forensic image hierarchy
/// (NTFS observed max is ~30 levels of nested folders in real-world
/// suspect images; the Strata test fixtures top out at 12). If the
/// lazy-load tree walker ever asks for children below this depth,
/// something has gone wrong — return an empty vec and log loudly so
/// the bug surfaces in the next run instead of locking up the UI.
const MAX_TREE_DEPTH: u32 = 50;

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

    // Sprint-10 P4 — short-circuit pathological recursion. If a node's
    // depth has grown past MAX_TREE_DEPTH something is feeding the
    // walker its own root back (the "Volume 0 (10223990784 bytes)
    // nested 20+ levels" symptom Sprint 8 surfaced on Charlie). Mark
    // the node as fully expanded with no children, log the cycle, and
    // return cleanly so the UI doesn't lock up.
    if depth >= MAX_TREE_DEPTH {
        log::warn!(
            "tree recursion guard fired for node {} at depth {} (>= {}); \
             returning empty children. vfs_path={:?}",
            node_id,
            depth,
            MAX_TREE_DEPTH,
            vfs_path
        );
        if let Some(node) = guard.nodes.get_mut(node_id) {
            node.children_loaded = true;
            node.child_ids.clear();
        }
        return Ok(Vec::new());
    }

    let entries = walk_directory(&guard, &vfs_path, vol_index)?;

    let mut new_child_ids = Vec::new();
    for entry in entries {
        // Sprint-10 P4 root-cause guard: if the VFS hands back an
        // entry whose path equals the directory we just walked, that
        // entry IS the parent — descending would loop forever (this
        // is the source of the "Volume 0 nested 20+ levels" symptom
        // Sprint 8 captured). Skip self-references; the depth limit
        // above is the load-bearing safety net but this stops the
        // cycle at depth=1 instead of letting it run to 50.
        if entry.path == vfs_path {
            log::warn!(
                "tree self-reference filtered: entry path {:?} == parent path {:?}",
                entry.path,
                vfs_path
            );
            continue;
        }
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

#[cfg(test)]
mod sprint11_p2_navigate_to_path_tests {
    //! Sprint-11 P2 — `navigate_to_path` resolves a source path to a
    //! tree node + breadcrumb, force-expanding lazy nodes along the
    //! way. Errors cleanly (no panic) when the path isn't present.

    use super::*;
    use crate::store::{insert_evidence, EVIDENCE_STORE};
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    fn unique_id() -> String {
        format!(
            "test-nav-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed),
        )
    }

    fn cleanup(id: &str) {
        let mut store = EVIDENCE_STORE.lock().expect("store");
        store.remove(id);
    }

    fn seed_evidence_with_dir(dir: &Path) -> String {
        let evidence_id = unique_id();
        let source = strata_fs::container::EvidenceSource::open(dir)
            .expect("EvidenceSource::open");
        let arc = insert_evidence(evidence_id.clone(), source);
        // Seed root + volume nodes so navigate_to_path has somewhere
        // to start. Mirrors the layout `parse_evidence` builds.
        {
            let mut guard = arc.lock().expect("lock");
            let root_id = "node-root".to_string();
            let vol_id = "node-root-vol-0".to_string();
            guard.nodes.insert(
                root_id.clone(),
                CachedNode {
                    id: root_id.clone(),
                    name: "evidence".into(),
                    node_type: "evidence".into(),
                    vfs_path: PathBuf::from("/"),
                    volume_index: None,
                    parent_id: None,
                    depth: 0,
                    child_ids: vec![vol_id.clone()],
                    children_loaded: true,
                },
            );
            guard.nodes.insert(
                vol_id.clone(),
                CachedNode {
                    id: vol_id,
                    name: "vol".into(),
                    node_type: "volume".into(),
                    vfs_path: dir.to_path_buf(),
                    volume_index: None,
                    parent_id: Some(root_id.clone()),
                    depth: 1,
                    child_ids: Vec::new(),
                    children_loaded: false,
                },
            );
            guard.root_node_ids = vec![root_id];
        }
        evidence_id
    }

    #[test]
    fn navigate_to_path_resolves_existing_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).expect("mkdir sub");
        std::fs::write(sub.join("evidence.txt"), b"x").expect("write");
        let eid = seed_evidence_with_dir(dir.path());

        // Navigate to the subdirectory itself — must return a node.
        let target = navigate_to_path(&eid, sub.to_str().expect("path"))
            .expect("subdir must resolve");
        assert!(!target.node_id.is_empty());
        assert!(
            target.breadcrumb.contains(&"node-root".to_string()),
            "breadcrumb must trace back to the root: {:?}",
            target.breadcrumb
        );

        // Navigate to a file — must return the parent dir's node id +
        // the file_id.
        let file_path = sub.join("evidence.txt");
        let target =
            navigate_to_path(&eid, file_path.to_str().expect("path")).expect("file resolves");
        assert!(target.file_id.is_some(), "file navigation must return file_id");
        cleanup(&eid);
    }

    #[test]
    fn navigate_to_path_returns_error_for_nonexistent_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let eid = seed_evidence_with_dir(dir.path());
        let bogus = "/nope/this/is/not/in/the/evidence";
        let result = navigate_to_path(&eid, bogus);
        match result {
            Err(AdapterError::NotFound(msg)) => {
                assert!(
                    msg.contains(bogus) || msg.contains("source path not found"),
                    "error message must mention the missing path: {msg}"
                );
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
        cleanup(&eid);
    }
}

#[cfg(test)]
mod sprint10_p4_tree_recursion_guard_tests {
    //! Sprint-10 P4 — verify the recursion safety net.
    //!
    //! These tests exercise `get_tree_children` directly against an
    //! evidence store seeded with a synthetic node at the limit. We
    //! do not need a real VFS because the guard runs *before* the
    //! VFS walk — that is the whole point of the safety net.

    use super::*;
    use crate::store::{insert_evidence, EVIDENCE_STORE};
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    fn unique_evidence_id() -> String {
        format!(
            "test-tree-ev-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed),
        )
    }

    fn cleanup(evidence_id: &str) {
        let mut store = EVIDENCE_STORE.lock().expect("evidence store");
        store.remove(evidence_id);
    }

    /// Synthesize an evidence entry with a single deep node so we can
    /// drive `get_tree_children` without a real forensic image.
    fn seed_evidence_with_node(node_id: &str, depth: u32) -> String {
        let evidence_id = unique_evidence_id();
        // Open a real-but-empty tempdir so EvidenceSource has a valid
        // VFS handle (irrelevant — the guard short-circuits before the
        // VFS is touched).
        let tmp = tempfile::tempdir().expect("tempdir");
        let source = strata_fs::container::EvidenceSource::open(tmp.path())
            .expect("EvidenceSource::open on tempdir");
        let arc = insert_evidence(evidence_id.clone(), source);
        {
            let mut guard = arc.lock().expect("evidence lock");
            guard.nodes.insert(
                node_id.to_string(),
                CachedNode {
                    id: node_id.to_string(),
                    name: "deep-node".to_string(),
                    node_type: "folder".to_string(),
                    vfs_path: PathBuf::from("/synthetic"),
                    volume_index: None,
                    parent_id: None,
                    depth,
                    child_ids: Vec::new(),
                    children_loaded: false,
                },
            );
        }
        evidence_id
    }

    #[test]
    fn depth_guard_returns_empty_at_or_above_max_depth() {
        let evidence_id = seed_evidence_with_node("deep-node-id", MAX_TREE_DEPTH);
        let result = get_tree_children(&evidence_id, "deep-node-id")
            .expect("guard must return Ok, not an error");
        assert!(
            result.is_empty(),
            "depth >= MAX_TREE_DEPTH must yield no children"
        );
        cleanup(&evidence_id);
    }

    #[test]
    fn depth_guard_marks_node_loaded_to_avoid_repeat_walks() {
        let evidence_id = seed_evidence_with_node("deep-node-id-2", MAX_TREE_DEPTH);
        let _ = get_tree_children(&evidence_id, "deep-node-id-2").expect("first call ok");
        // Second call must not re-trigger the walk path. Easiest way to
        // verify: confirm the cached `children_loaded` flag is set so the
        // early-return branch fires.
        let arc = crate::store::get_evidence(&evidence_id).expect("store lookup");
        let guard = arc.lock().expect("lock");
        let node = guard
            .nodes
            .get("deep-node-id-2")
            .expect("node still present");
        assert!(
            node.children_loaded,
            "guard must mark the node loaded so it is not re-walked"
        );
        assert!(node.child_ids.is_empty(), "guard must clear stale child ids");
        drop(guard);
        cleanup(&evidence_id);
    }
}
