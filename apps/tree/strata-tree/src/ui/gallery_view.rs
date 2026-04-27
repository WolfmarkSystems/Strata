//! Gallery view — thumbnail grid for image files with bounded LRU cache.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;

use egui::TextureOptions;

use crate::state::{colors::*, AppState};

const THUMB_SIZE: u32 = 128;
const THUMB_CACHE_CAP: usize = 500;

struct ThumbMsg {
    file_id: String,
    image: Result<egui::ColorImage, String>,
}

#[derive(Default)]
struct GalleryCache {
    textures: HashMap<String, egui::TextureHandle>,
    order: VecDeque<String>,
    failed: HashSet<String>,
    loading: HashSet<String>,
    rx: Option<Receiver<ThumbMsg>>,
    selection_key: String,
}

thread_local! {
    static CACHE: std::cell::RefCell<GalleryCache> = std::cell::RefCell::new(GalleryCache::default());
}

pub fn render(ui: &mut egui::Ui, state: &mut AppState) {
    let selected_dir = state.file_filter.clone();
    let min_size = state.gallery_min_size;
    let max_size = state.gallery_max_size;
    let ext_filter = state.gallery_ext_filter.to_lowercase();

    let images: Vec<crate::state::FileEntry> = state
        .file_index
        .iter()
        .filter(|f| !f.is_dir && f.category.as_deref() == Some("Image"))
        .filter(|f| {
            selected_dir.is_empty()
                || f.parent_path == selected_dir
                || f.path.starts_with(&selected_dir)
        })
        .filter(|f| {
            if min_size > 0 && f.size.unwrap_or(0) < min_size {
                return false;
            }
            if max_size > 0 && f.size.unwrap_or(0) > max_size {
                return false;
            }
            if !ext_filter.is_empty() {
                let fext = f.extension.as_deref().unwrap_or("").to_lowercase();
                if !fext.contains(&ext_filter) {
                    return false;
                }
            }
            true
        })
        .cloned()
        .collect();

    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new("GALLERY")
                .color(ACCENT)
                .size(11.0)
                .strong(),
        );
        ui.separator();
        ui.label(
            egui::RichText::new(format!("{} images", images.len()))
                .color(TEXT_MUTED)
                .size(9.5),
        );
    });

    // Gallery filter controls
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("Filter:").color(TEXT_MUTED).size(8.5));
        ui.label(egui::RichText::new("ext").color(TEXT_MUTED).size(8.0));
        ui.add(
            egui::TextEdit::singleline(&mut state.gallery_ext_filter)
                .desired_width(50.0)
                .hint_text("jpg"),
        );
        ui.label(egui::RichText::new("min KB").color(TEXT_MUTED).size(8.0));
        let mut min_str = if state.gallery_min_size > 0 {
            (state.gallery_min_size / 1024).to_string()
        } else {
            String::new()
        };
        if ui
            .add(
                egui::TextEdit::singleline(&mut min_str)
                    .desired_width(40.0)
                    .hint_text("0"),
            )
            .changed()
        {
            state.gallery_min_size = min_str.parse::<u64>().unwrap_or(0) * 1024;
        }
        ui.label(egui::RichText::new("max KB").color(TEXT_MUTED).size(8.0));
        let mut max_str = if state.gallery_max_size > 0 {
            (state.gallery_max_size / 1024).to_string()
        } else {
            String::new()
        };
        if ui
            .add(
                egui::TextEdit::singleline(&mut max_str)
                    .desired_width(40.0)
                    .hint_text("∞"),
            )
            .changed()
        {
            state.gallery_max_size = max_str.parse::<u64>().unwrap_or(0) * 1024;
        }
        if ui.button("Clear").clicked() {
            state.gallery_ext_filter.clear();
            state.gallery_min_size = 0;
            state.gallery_max_size = 0;
        }
    });
    ui.add_space(4.0);

    if images.is_empty() {
        ui.label(egui::RichText::new("No image files in the current selection.").color(TEXT_MUTED));
        return;
    }

    CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if cache.selection_key != selected_dir {
            cache.selection_key = selected_dir.clone();
        }
        drain_thumb_messages(&mut cache, ui.ctx());

        let cols = 4usize;
        let row_h = THUMB_SIZE as f32 + 28.0;
        let row_count = images.len().div_ceil(cols);
        let mut load_batch: Vec<crate::state::FileEntry> = Vec::new();
        egui::ScrollArea::vertical().show_rows(ui, row_h, row_count, |ui, range| {
            for row in range {
                ui.horizontal(|ui| {
                    for col in 0..cols {
                        let idx = row * cols + col;
                        if idx >= images.len() {
                            break;
                        }
                        let file = &images[idx];
                        ui.vertical(|ui| {
                            let tex = cache.textures.get(&file.id).cloned();
                            let is_loading = cache.loading.contains(&file.id);
                            let is_failed = cache.failed.contains(&file.id);

                            let button_label = if let Some(texture) = tex {
                                let img = egui::Image::new((
                                    texture.id(),
                                    egui::vec2(THUMB_SIZE as f32, THUMB_SIZE as f32),
                                ));
                                let resp = ui.add(egui::ImageButton::new(img));
                                if resp.clicked() {
                                    state.selected_file_id = Some(file.id.clone());
                                    state.preview_tab = 3;
                                }
                                resp
                            } else if is_loading {
                                ui.add_sized(
                                    [THUMB_SIZE as f32, THUMB_SIZE as f32],
                                    egui::Label::new(
                                        egui::RichText::new("Loading...").color(TEXT_MUTED),
                                    ),
                                )
                            } else if is_failed {
                                ui.add_sized(
                                    [THUMB_SIZE as f32, THUMB_SIZE as f32],
                                    egui::Label::new(
                                        egui::RichText::new("Decode error").color(DANGER),
                                    ),
                                )
                            } else {
                                load_batch.push(file.clone());
                                ui.add_sized(
                                    [THUMB_SIZE as f32, THUMB_SIZE as f32],
                                    egui::Label::new(
                                        egui::RichText::new("Queued").color(TEXT_MUTED),
                                    ),
                                )
                            };

                            button_label.context_menu(|ui| {
                                if ui.button("Bookmark").clicked() {
                                    state.active_tag = "NOTABLE".to_string();
                                    state.selected_file_id = Some(file.id.clone());
                                    state.status = format!("Ready to bookmark: {}", file.name);
                                    ui.close_menu();
                                }
                                if ui.button("Add examiner note").clicked() {
                                    state.selected_file_id = Some(file.id.clone());
                                    state.status =
                                        format!("Add note in preview panel for {}", file.name);
                                    ui.close_menu();
                                }
                                if ui.button("Export file").clicked() {
                                    if let Some(dest) =
                                        rfd::FileDialog::new().set_file_name(&file.name).save_file()
                                    {
                                        if let Err(err) =
                                            state.ensure_output_path_safe(dest.as_path())
                                        {
                                            state.status = err;
                                            ui.close_menu();
                                            return;
                                        }
                                        match read_file_bytes(state.vfs_context.as_deref(), file) {
                                            Ok(bytes) => match std::fs::write(&dest, bytes) {
                                                Ok(_) => {
                                                    state.status =
                                                        format!("Exported {}", dest.display())
                                                }
                                                Err(e) => {
                                                    state.status = format!("Export failed: {}", e)
                                                }
                                            },
                                            Err(e) => {
                                                state.status = format!("Export failed: {}", e)
                                            }
                                        }
                                    }
                                    ui.close_menu();
                                }
                                if ui.button("Hash file").clicked() {
                                    if !state.hashing_active {
                                        let (tx, rx) = std::sync::mpsc::channel();
                                        crate::evidence::hasher::spawn_hash_worker(
                                            vec![file.clone()],
                                            state.vfs_context.clone(),
                                            tx,
                                        );
                                        state.hashing_rx = Some(rx);
                                        state.hashing_active = true;
                                        state.status = format!("Hashing {}", file.name);
                                    }
                                    ui.close_menu();
                                }
                            });

                            ui.label(egui::RichText::new(&file.name).size(8.5).color(TEXT_SEC));
                        });
                    }
                });
            }
        });

        if !load_batch.is_empty() && cache.rx.is_none() {
            spawn_thumb_worker(&mut cache, &load_batch, state.vfs_context.clone());
        }
    });
}

fn spawn_thumb_worker(
    cache: &mut GalleryCache,
    images: &[crate::state::FileEntry],
    ctx: Option<Arc<crate::evidence::vfs_context::VfsReadContext>>,
) {
    if cache.rx.is_some() {
        return;
    }
    let mut queue = Vec::new();
    for file in images {
        if !cache.textures.contains_key(&file.id)
            && !cache.failed.contains(&file.id)
            && cache.loading.insert(file.id.clone())
        {
            queue.push(file.clone());
        }
    }

    if queue.is_empty() {
        return;
    }

    let (tx, rx) = mpsc::channel::<ThumbMsg>();
    std::thread::spawn(move || {
        for file in queue {
            let image = load_thumb(ctx.as_deref(), &file);
            let _ = tx.send(ThumbMsg {
                file_id: file.id.clone(),
                image,
            });
        }
    });
    cache.rx = Some(rx);
}

fn drain_thumb_messages(cache: &mut GalleryCache, ctx: &egui::Context) {
    let mut msgs = Vec::new();
    let mut disconnected = false;
    if let Some(rx) = &cache.rx {
        loop {
            match rx.try_recv() {
                Ok(msg) => msgs.push(msg),
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    disconnected = true;
                    break;
                }
            }
        }
    }
    if disconnected {
        cache.rx = None;
    }
    for msg in msgs {
        cache.loading.remove(&msg.file_id);
        match msg.image {
            Ok(ci) => {
                let tex = ctx.load_texture(msg.file_id.clone(), ci, TextureOptions::LINEAR);
                cache.textures.insert(msg.file_id.clone(), tex);
                touch_lru(cache, &msg.file_id);
                evict_lru(cache);
            }
            Err(_) => {
                cache.failed.insert(msg.file_id);
            }
        }
    }
}

fn touch_lru(cache: &mut GalleryCache, file_id: &str) {
    if let Some(pos) = cache.order.iter().position(|x| x == file_id) {
        cache.order.remove(pos);
    }
    cache.order.push_back(file_id.to_string());
}

fn evict_lru(cache: &mut GalleryCache) {
    while cache.textures.len() > THUMB_CACHE_CAP {
        if let Some(oldest) = cache.order.pop_front() {
            cache.textures.remove(&oldest);
        } else {
            break;
        }
    }
}

fn load_thumb(
    ctx: Option<&crate::evidence::vfs_context::VfsReadContext>,
    file: &crate::state::FileEntry,
) -> Result<egui::ColorImage, String> {
    let buf = read_file_bytes(ctx, file)?;
    let img = image::load_from_memory(&buf).map_err(|e| format!("decode: {}", e))?;
    let thumb = img.thumbnail(THUMB_SIZE, THUMB_SIZE).to_rgba8();
    let (w, h) = thumb.dimensions();
    Ok(egui::ColorImage::from_rgba_unmultiplied(
        [w as usize, h as usize],
        thumb.as_raw(),
    ))
}

fn read_file_bytes(
    ctx: Option<&crate::evidence::vfs_context::VfsReadContext>,
    file: &crate::state::FileEntry,
) -> Result<Vec<u8>, String> {
    const THUMB_READ_MAX: usize = 512 * 1024;
    if let Some(ctx) = ctx {
        return ctx
            .read_range(file, 0, THUMB_READ_MAX)
            .map_err(|e| e.to_string());
    }
    Err("VFS read context unavailable".to_string())
}
