pub mod carve_dialog;
pub mod examiner_setup;
pub mod export;
pub mod new_case;
pub mod open_evidence;
pub mod search;

use crate::state::AppState;

pub fn render(ctx: &egui::Context, state: &mut AppState) {
    examiner_setup::render(ctx, state);
    if state.open_ev_dlg.open {
        open_evidence::render(ctx, state);
    }
    if state.new_case_dlg.open {
        new_case::render(ctx, state);
    }
    if state.show_carve_dialog {
        carve_dialog::render(ctx, state);
    }
    search::render(ctx, state);
    export::render(ctx, state);
}
