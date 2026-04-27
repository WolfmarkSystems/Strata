//! Left pane — Evidence Tree.

use crate::state::AppState;
use std::collections::HashMap;

#[allow(dead_code)]
struct TreeCache {
    /// Number of files when cache was built.
    file_count: usize,
    /// Cached tree per evidence source ID.
    trees: HashMap<String, Vec<DirTreeNode>>,
}

thread_local! {
    static DIR_TREE_CACHE: std::cell::RefCell<TreeCache> = std::cell::RefCell::new(TreeCache {
        file_count: 0,
        trees: HashMap::new(),
    });
}

pub fn render(ui: &mut egui::Ui, state: &mut AppState) {
    let t = *state.theme();
    egui::Frame::none()
        .inner_margin(egui::Margin {
            left: 8.0,
            right: 4.0,
            top: 6.0,
            bottom: 4.0,
        })
        .show(ui, |ui| {
            header(ui, "EVIDENCE TREE", state.evidence_sources.len(), &t);
        });
    ui.separator();

    egui::Frame::none()
        .inner_margin(egui::Margin {
            left: 6.0,
            right: 6.0,
            top: 2.0,
            bottom: 2.0,
        })
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("FILTER").color(t.muted).size(8.0));
                let resp = ui.text_edit_singleline(&mut state.file_filter);
                if resp.changed() {
                    state.mark_filter_dirty();
                }
                resp.context_menu(|ui| {
                    if ui.button("Clear Filter").clicked() {
                        state.file_filter.clear();
                        state.mark_filter_dirty();
                        ui.close_menu();
                    }
                    if ui.button("Copy Filter").clicked() {
                        ui.ctx().copy_text(state.file_filter.clone());
                        ui.close_menu();
                    }
                });
            });
        });
    ui.separator();

    egui::ScrollArea::vertical().show(ui, |ui| {
        egui::Frame::none()
            .inner_margin(egui::Margin {
                left: 4.0,
                right: 4.0,
                top: 4.0,
                bottom: 4.0,
            })
            .show(ui, |ui| {
                if state.evidence_sources.is_empty() {
                    ui.add_space(12.0);
                    ui.label(
                        egui::RichText::new("No evidence loaded.")
                            .color(t.muted)
                            .size(10.0),
                    );
                    ui.label(
                        egui::RichText::new("Click OPEN EVIDENCE to begin.")
                            .color(t.muted)
                            .size(9.0),
                    );
                    return;
                }

                for src in &state.evidence_sources.clone() {
                    let badge_color = match src.format.as_str() {
                        "E01" | "EWF" => t.suspicious,
                        "NTFS" | "DD" | "RAW" => t.active,
                        "Directory" => t.clean,
                        _ => t.muted,
                    };

                    // Show filename only, full path in tooltip
                    let full_path = &src.path;
                    let file_name = std::path::Path::new(full_path)
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| truncate(full_path, 28));
                    let size_str = src.size_bytes.map(fmt_bytes).unwrap_or_default();
                    let header_text = if size_str.is_empty() {
                        format!("\u{1F4BF} {}", file_name)
                    } else {
                        format!("\u{1F4BF} {} ({})", file_name, size_str)
                    };

                    let resp = egui::CollapsingHeader::new(
                        egui::RichText::new(&header_text).color(t.active).size(10.0),
                    )
                    .id_source(&src.id)
                    .default_open(true)
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.add_space(4.0);
                            ui.label(
                                egui::RichText::new(&src.format)
                                    .color(badge_color)
                                    .size(8.5)
                                    .strong(),
                            );
                            let (health_label, health_color) =
                                evidence_health(state, &src.id, src.hash_verified, &t);
                            ui.separator();
                            ui.label(
                                egui::RichText::new(format!("{} {}", "\u{25cf}", health_label))
                                    .color(health_color)
                                    .size(8.0),
                            );
                        });

                        // Lazy directory tree — collect immediate children of root only
                        let src_id_owned = src.id.clone();
                        render_lazy_tree(ui, state, &src_id_owned, "", &t, 0);

                        let carved = carved_signature_counts(&state.file_index, &src.id);
                        let carved_total: usize = carved.iter().map(|(_, count)| *count).sum();
                        if carved_total > 0 {
                            egui::CollapsingHeader::new(
                                egui::RichText::new(format!(
                                    "  \u{25b8} $CARVED ({})",
                                    carved_total
                                ))
                                .color(t.suspicious)
                                .size(9.5),
                            )
                            .default_open(true)
                            .show(ui, |ui| {
                                for (sig, count) in carved {
                                    let p = format!("$CARVED/{}", sig);
                                    let selected =
                                        state.selected_tree_path.as_deref() == Some(p.as_str());
                                    let node_resp = ui.selectable_label(
                                        selected,
                                        egui::RichText::new(format!(
                                            "    \u{25b8} {} ({})",
                                            sig, count
                                        ))
                                        .color(t.suspicious)
                                        .size(9.0),
                                    );
                                    if node_resp.clicked() {
                                        state.selected_tree_path = Some(p.clone());
                                        state.file_filter = p;
                                        state.mark_filter_dirty();
                                    }
                                }
                            });
                        }
                    });
                    // Always show full path in tooltip for evidence root node.
                    let header_resp = resp.header_response.clone();
                    header_resp.clone().on_hover_text(full_path.as_str());
                    header_resp.context_menu(|ui| {
                        if ui.button("Copy Evidence Path").clicked() {
                            ui.ctx().copy_text(full_path.clone());
                            ui.close_menu();
                        }
                        if ui.button("Filter Evidence").clicked() {
                            state.selected_tree_path = Some(src.id.clone());
                            state.file_filter = src.id.clone();
                            state.mark_filter_dirty();
                            ui.close_menu();
                        }
                    });
                }
            });
    });
}

fn header(ui: &mut egui::Ui, title: &str, count: usize, t: &crate::theme::StrataTheme) {
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new(title).color(t.muted).size(8.5).strong());
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(
                egui::RichText::new(count.to_string())
                    .color(t.active)
                    .size(8.5),
            );
        });
    });
}

/// Lazy directory tree — builds only visible children on demand.
/// This approach scales to 100K+ files without freezing because it
/// never iterates all files to build a full tree. It only collects
/// the immediate children of the currently-expanded directory.
fn render_lazy_tree(
    ui: &mut egui::Ui,
    state: &mut AppState,
    evidence_id: &str,
    parent_prefix: &str,
    t: &crate::theme::StrataTheme,
    depth: usize,
) {
    if depth > 10 {
        return;
    }

    // Collect immediate child directories of parent_prefix
    let children = collect_immediate_children(&state.file_index, evidence_id, parent_prefix);

    let max_show = if depth == 0 { 60 } else { 40 };

    for (idx, (child_name, child_path, file_count)) in children.iter().enumerate() {
        if idx >= max_show {
            ui.label(
                egui::RichText::new(format!("  … {} more", children.len() - max_show))
                    .color(t.muted)
                    .size(8.5),
            );
            break;
        }

        let selected = state.selected_tree_path.as_deref() == Some(child_path.as_str());

        // Check if this directory has subdirectories
        let has_subdirs = has_child_dirs(&state.file_index, evidence_id, child_path);

        let count_suffix = if *file_count > 0 {
            format!(" ({})", file_count)
        } else {
            String::new()
        };

        if has_subdirs {
            let header_text = format!("\u{1F4C1} {}{}", child_name, count_suffix);
            let resp = egui::CollapsingHeader::new(
                egui::RichText::new(&header_text)
                    .color(if selected { t.active } else { t.secondary })
                    .size(9.5),
            )
            .id_source(child_path)
            .default_open(depth == 0 && idx < 5)
            .show(ui, |ui| {
                // Lazy: children only built when header is expanded
                render_lazy_tree(ui, state, evidence_id, child_path, t, depth + 1);
            });

            let hr = &resp.header_response;
            if hr.clicked() {
                state.selected_tree_path = Some(child_path.clone());
                state.file_filter = child_path.clone();
                state.mark_filter_dirty();
            }
            hr.clone().on_hover_text(child_path.as_str());
        } else {
            let label_text = format!("  \u{1F4C1} {}{}", child_name, count_suffix);
            let resp = ui.selectable_label(
                selected,
                egui::RichText::new(&label_text)
                    .color(if selected { t.active } else { t.secondary })
                    .size(9.5),
            );
            if resp.clicked() {
                state.selected_tree_path = Some(child_path.clone());
                state.file_filter = child_path.clone();
                state.mark_filter_dirty();
            }
            resp.on_hover_text(child_path.as_str());
        }
    }
}

/// Collect immediate child directory names of a given parent path.
/// Only scans parent_path field — O(n) but deduplicates into a BTreeSet
/// which caps at the number of unique immediate children.
fn collect_immediate_children(
    files: &[crate::state::FileEntry],
    evidence_id: &str,
    parent_prefix: &str,
) -> Vec<(String, String, usize)> {
    use std::collections::BTreeMap;

    let mut child_counts: BTreeMap<String, usize> = BTreeMap::new();

    for f in files {
        if f.evidence_id != evidence_id {
            continue;
        }
        let parent = &f.parent_path;

        if parent_prefix.is_empty() {
            // Root level: extract first path segment
            if let Some(first) = first_segment(parent) {
                *child_counts.entry(first).or_default() += if f.is_dir { 0 } else { 1 };
            }
        } else if parent.starts_with(parent_prefix) && parent.len() > parent_prefix.len() {
            // Child of this prefix
            let rest = &parent[parent_prefix.len()..];
            let rest = rest.trim_start_matches(['/', ' ']);
            if rest.is_empty() {
                // File directly in this directory
                continue;
            }
            if let Some(seg) = rest.split('/').next() {
                if !seg.is_empty() {
                    let child_path = format!("{}/{}", parent_prefix, seg);
                    *child_counts.entry(child_path).or_default() += if f.is_dir { 0 } else { 1 };
                }
            }
        } else if parent == parent_prefix && !f.is_dir {
            // File directly in this directory — count but don't create subdirectory
        }
    }

    child_counts
        .into_iter()
        .map(|(path, count)| {
            let name = path.rsplit('/').next().unwrap_or(&path).to_string();
            (name, path, count)
        })
        .collect()
}

/// Check if a directory path has any subdirectories.
fn has_child_dirs(files: &[crate::state::FileEntry], evidence_id: &str, prefix: &str) -> bool {
    for f in files {
        if f.evidence_id != evidence_id {
            continue;
        }
        if f.parent_path.starts_with(prefix) && f.parent_path.len() > prefix.len() + 1 {
            let rest = &f.parent_path[prefix.len()..];
            let rest = rest.trim_start_matches(['/', ' ']);
            if rest.contains('/') || !rest.is_empty() {
                return true;
            }
        }
    }
    false
}

fn first_segment(path: &str) -> Option<String> {
    let trimmed = path.trim_start_matches(['/', ' ']);
    if trimmed.is_empty() {
        return None;
    }
    // For paths like "[NTFS NTFS] /ntfs_vol0/Windows/..."
    // The first "segment" is everything up to the second real path component
    Some(trimmed.split('/').take(1).collect::<Vec<_>>().join("/"))
}

#[derive(Clone)]
#[allow(dead_code)]
struct DirTreeNode {
    name: String,
    full_path: String,
    children: Vec<DirTreeNode>,
    file_count: usize,
}

// Legacy — kept for reference but no longer called
#[allow(dead_code)]
fn build_dir_tree(files: &[crate::state::FileEntry], evidence_id: &str) -> Vec<DirTreeNode> {
    use std::collections::BTreeMap;

    // Count files per parent_path — only track directories that have files
    let mut file_counts: BTreeMap<String, usize> = BTreeMap::new();

    for f in files {
        if f.evidence_id != evidence_id || f.is_dir {
            continue;
        }
        let parent = f.parent_path.replace('\\', "/");
        if parent.is_empty() || parent == "." || parent.starts_with("$CARVED") {
            continue;
        }
        *file_counts.entry(parent).or_default() += 1;
    }

    // Build all_dirs from file_counts + ancestors (but limit depth)
    let mut all_dirs: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for dir in file_counts.keys() {
        all_dirs.insert(dir.clone());
        // Walk up to 6 ancestor levels
        let mut current = dir.as_str();
        for _ in 0..6 {
            if let Some(slash) = current.rfind('/') {
                let ancestor = &current[..slash];
                if ancestor.is_empty() || ancestor == "." || all_dirs.contains(ancestor) {
                    break;
                }
                all_dirs.insert(ancestor.to_string());
                current = ancestor;
            } else {
                break;
            }
        }
    }

    // Build a prefix-based tree
    // Find the common prefix (e.g., "[NTFS NTFS] /ntfs_vol0")
    let sorted_dirs: Vec<String> = all_dirs.into_iter().collect();
    if sorted_dirs.is_empty() {
        return Vec::new();
    }

    // Find the root prefix — the shortest path that contains most entries
    let prefix = find_common_prefix(&sorted_dirs);

    // Build tree recursively from the prefix
    build_children(&sorted_dirs, &file_counts, &prefix)
}

fn find_common_prefix(dirs: &[String]) -> String {
    if dirs.is_empty() {
        return String::new();
    }

    // Find the longest common prefix shared by ALL directory paths.
    // This handles patterns like "[NTFS NTFS] /ntfs_vol0" correctly.
    let first = dirs[0].as_bytes();
    let mut prefix_len = first.len();

    for dir in &dirs[1..] {
        let b = dir.as_bytes();
        let common = first
            .iter()
            .zip(b.iter())
            .take_while(|(a, b)| a == b)
            .count();
        prefix_len = prefix_len.min(common);
        if prefix_len == 0 {
            return String::new();
        }
    }

    // Trim to last '/' boundary so we don't split mid-segment
    let prefix = &dirs[0][..prefix_len];
    if let Some(last_slash) = prefix.rfind('/') {
        prefix[..last_slash].to_string()
    } else {
        prefix.to_string()
    }
}

fn build_children(
    all_dirs: &[String],
    file_counts: &std::collections::BTreeMap<String, usize>,
    parent_prefix: &str,
) -> Vec<DirTreeNode> {
    use std::collections::BTreeMap;

    // Find direct children of parent_prefix
    let mut child_map: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for dir in all_dirs {
        if dir == parent_prefix {
            continue;
        }
        // Check if this dir is a direct child of parent_prefix
        let stripped = if parent_prefix.is_empty() {
            dir.as_str()
        } else if let Some(rest) = dir.strip_prefix(parent_prefix) {
            let rest = rest.trim_start_matches(['/', ' ']);
            rest
        } else {
            continue;
        };

        if stripped.is_empty() {
            continue;
        }

        // Get the first path segment after the prefix
        let first_segment = if let Some(slash_pos) = stripped.find('/') {
            &stripped[..slash_pos]
        } else {
            stripped
        };

        if first_segment.is_empty() {
            continue;
        }

        let child_full_path = if parent_prefix.is_empty() {
            first_segment.to_string()
        } else if parent_prefix.ends_with('/') || parent_prefix.ends_with(' ') {
            format!("{}{}", parent_prefix, first_segment)
        } else {
            format!("{}/{}", parent_prefix, first_segment)
        };

        child_map.entry(child_full_path).or_default();
    }

    let mut children: Vec<DirTreeNode> = Vec::new();

    for child_path in child_map.keys() {
        let name = child_path
            .rsplit('/')
            .next()
            .unwrap_or(child_path)
            .to_string();
        let fc = file_counts.get(child_path).copied().unwrap_or(0);

        // Recursively build grandchildren
        let grandchildren = build_children(all_dirs, file_counts, child_path);

        children.push(DirTreeNode {
            name,
            full_path: child_path.clone(),
            children: grandchildren,
            file_count: fc,
        });
    }

    children
}

#[allow(dead_code)]
fn render_dir_tree(
    ui: &mut egui::Ui,
    state: &mut AppState,
    nodes: &[DirTreeNode],
    t: &crate::theme::StrataTheme,
    depth: usize,
) {
    if depth > 8 || nodes.is_empty() {
        return;
    }

    // Limit visible children per level to keep UI responsive
    let max_visible = if depth == 0 { 50 } else { 30 };
    let truncated = nodes.len() > max_visible;

    for node in nodes.iter().take(max_visible) {
        let selected = state.selected_tree_path.as_deref() == Some(node.full_path.as_str());
        let has_children = !node.children.is_empty();

        let count_suffix = if node.file_count > 0 {
            format!(" ({})", node.file_count)
        } else {
            String::new()
        };

        if has_children {
            let header_text = format!("\u{1F4C1} {}{}", node.name, count_suffix);
            let resp = egui::CollapsingHeader::new(
                egui::RichText::new(&header_text)
                    .color(if selected { t.active } else { t.secondary })
                    .size(9.5),
            )
            .id_source(&node.full_path)
            .default_open(depth == 0) // Only auto-open top level
            .show(ui, |ui| {
                render_dir_tree(ui, state, &node.children, t, depth + 1);
            });

            // Click on header selects this directory
            let hr = &resp.header_response;
            if hr.clicked() {
                state.selected_tree_path = Some(node.full_path.clone());
                state.file_filter = node.full_path.clone();
                state.mark_filter_dirty();
            }
            hr.clone().on_hover_text(&node.full_path);
            hr.clone().context_menu(|ui| {
                if ui.button("Copy Path").clicked() {
                    ui.ctx().copy_text(node.full_path.clone());
                    ui.close_menu();
                }
                if ui.button("Filter Here").clicked() {
                    state.selected_tree_path = Some(node.full_path.clone());
                    state.file_filter = node.full_path.clone();
                    state.mark_filter_dirty();
                    ui.close_menu();
                }
            });
        } else {
            // Leaf directory — no collapsing header needed
            let label_text = format!("  \u{1F4C1} {}{}", node.name, count_suffix);
            let label = egui::RichText::new(&label_text)
                .color(if selected { t.active } else { t.secondary })
                .size(9.5);
            let resp = ui.selectable_label(selected, label);
            resp.clone().on_hover_text(&node.full_path);
            if resp.clicked() {
                state.selected_tree_path = Some(node.full_path.clone());
                state.file_filter = node.full_path.clone();
                state.mark_filter_dirty();
            }
            resp.context_menu(|ui| {
                if ui.button("Copy Path").clicked() {
                    ui.ctx().copy_text(node.full_path.clone());
                    ui.close_menu();
                }
            });
        }
    }

    if truncated {
        ui.label(
            egui::RichText::new(format!(
                "  … {} more directories",
                nodes.len() - max_visible
            ))
            .color(t.muted)
            .size(8.5),
        );
    }
}

fn carved_signature_counts(
    files: &[crate::state::FileEntry],
    evidence_id: &str,
) -> Vec<(String, usize)> {
    let mut counts = std::collections::BTreeMap::<String, usize>::new();
    for f in files {
        if f.evidence_id != evidence_id || !f.is_carved {
            continue;
        }
        let sig = f
            .parent_path
            .strip_prefix("$CARVED/")
            .map(|s| s.to_string())
            .unwrap_or_else(|| "Unknown".to_string());
        *counts.entry(sig).or_insert(0usize) += 1;
    }
    let mut ordered: Vec<(String, usize)> = counts.into_iter().collect();
    ordered.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    ordered
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        return s.to_string();
    }
    format!("\u{2026}{}", &s[s.len() - n..])
}

fn fmt_bytes(b: u64) -> String {
    const GB: u64 = 1 << 30;
    const MB: u64 = 1 << 20;
    const KB: u64 = 1 << 10;
    if b >= GB {
        format!("{:.1} GB", b as f64 / GB as f64)
    } else if b >= MB {
        format!("{:.1} MB", b as f64 / MB as f64)
    } else if b >= KB {
        format!("{:.0} KB", b as f64 / KB as f64)
    } else {
        format!("{} B", b)
    }
}

fn evidence_health(
    state: &AppState,
    evidence_id: &str,
    hash_verified: bool,
    t: &crate::theme::StrataTheme,
) -> (&'static str, egui::Color32) {
    let files = state
        .file_index
        .iter()
        .filter(|f| !f.is_dir && f.evidence_id == evidence_id)
        .count();
    if files == 0 {
        return ("NO FILES", t.flagged);
    }
    if hash_verified {
        return ("VERIFIED", t.clean);
    }
    ("UNVERIFIED", t.suspicious)
}
