// ui/gallery.rs — Image thumbnail gallery (Phase 2, Task 2.3).
//
// Displays all image-category files as a lazy-loaded thumbnail grid.
// Thumbnails are 128×128 pixels, decoded on-demand from disk using the `image` crate.
// Textures are cached in AppState::gallery to avoid re-decoding every frame.
// Clicking a thumbnail selects that file in the main file table.

use egui::{ScrollArea, TextureOptions, Vec2};
use crate::state::AppState;

const THUMB_SIZE: f32 = 128.0;
const THUMB_COLS: usize = 6;
const MAX_THUMB_PX: u32 = 128;

pub fn render(ui: &mut egui::Ui, state: &mut AppState) {
    ui.heading("Image Gallery");
    ui.separator();

    // Collect image files.
    let image_files: Vec<_> = state.file_index.iter()
        .filter(|f| !f.is_dir && matches!(
            f.category.as_deref(),
            Some("Image")
        ))
        .map(|f| (f.id.clone(), f.path.clone(), f.name.clone()))
        .collect();

    if image_files.is_empty() {
        ui.label("No image files found in the current case.");
        return;
    }

    ui.label(format!("{} images", image_files.len()));
    ui.separator();

    ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            let avail_width = ui.available_width();
            let cell_width = (THUMB_SIZE + 8.0).max(1.0);
            let cols = ((avail_width / cell_width) as usize).max(1).min(THUMB_COLS);

            egui::Grid::new("gallery_grid")
                .num_columns(cols)
                .spacing([4.0, 4.0])
                .show(ui, |ui| {
                    for (col_idx, (file_id, file_path, file_name)) in image_files.iter().enumerate() {
                        // Load texture if not cached.
                        let texture = if state.gallery.thumbnails.contains_key(file_id.as_str()) {
                            Some(state.gallery.thumbnails[file_id.as_str()].clone())
                        } else if state.gallery.failed.contains(file_id.as_str()) {
                            None
                        } else {
                            match load_thumbnail(file_path) {
                                Ok(color_image) => {
                                    let handle = ui.ctx().load_texture(
                                        file_id.as_str(),
                                        color_image,
                                        TextureOptions::LINEAR,
                                    );
                                    state.gallery.thumbnails.insert(file_id.clone(), handle.clone());
                                    Some(handle)
                                }
                                Err(_) => {
                                    state.gallery.failed.insert(file_id.clone());
                                    None
                                }
                            }
                        };

                        // Draw cell.
                        let is_selected = state.selected_file.as_deref() == Some(file_id);
                        let (rect, response) = ui.allocate_exact_size(
                            Vec2::splat(THUMB_SIZE + 4.0),
                            egui::Sense::click(),
                        );

                        if ui.is_rect_visible(rect) {
                            let bg_color = if is_selected {
                                egui::Color32::from_rgb(60, 80, 120)
                            } else {
                                egui::Color32::from_rgb(40, 40, 40)
                            };
                            ui.painter().rect_filled(rect, 2.0, bg_color);

                            let inner = rect.shrink(2.0);
                            if let Some(tex) = texture {
                                ui.painter().image(
                                    tex.id(),
                                    inner,
                                    egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)),
                                    egui::Color32::WHITE,
                                );
                            } else {
                                // Placeholder for broken image.
                                ui.painter().rect_filled(inner, 0.0, egui::Color32::from_rgb(60, 40, 40));
                                ui.painter().text(
                                    inner.center(),
                                    egui::Align2::CENTER_CENTER,
                                    "?",
                                    egui::FontId::monospace(24.0),
                                    egui::Color32::from_rgb(180, 80, 80),
                                );
                            }
                        }

                        if response.clicked() {
                            state.selected_file = Some(file_id.clone());
                        }

                        response.on_hover_text(file_name.as_str());

                        if (col_idx + 1) % cols == 0 {
                            ui.end_row();
                        }
                    }
                });
        });
}

/// Decode an image file and produce a 128×128 thumbnail as an egui ColorImage.
fn load_thumbnail(path: &str) -> anyhow::Result<egui::ColorImage> {
    let img = image::open(path)?;
    let thumb = img.thumbnail(MAX_THUMB_PX, MAX_THUMB_PX);
    let rgba = thumb.to_rgba8();
    let (w, h) = rgba.dimensions();
    let pixels: Vec<egui::Color32> = rgba
        .chunks_exact(4)
        .map(|p| egui::Color32::from_rgba_unmultiplied(p[0], p[1], p[2], p[3]))
        .collect();
    Ok(egui::ColorImage {
        size: [w as usize, h as usize],
        pixels,
    })
}
