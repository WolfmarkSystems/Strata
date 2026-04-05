// evidence/watcher.rs — Receives indexing progress and updates AppState.
// Call poll() each frame to drain the channel.

use std::sync::mpsc::Receiver;
use crate::state::{AppState, IndexingStatus};
use super::indexer::IndexingProgress;

pub struct IndexingWatcher {
    pub rx: Receiver<IndexingProgress>,
}

impl IndexingWatcher {
    pub fn new(rx: Receiver<IndexingProgress>) -> Self {
        Self { rx }
    }

    /// Drain available progress messages and update state. Call once per frame.
    pub fn poll(&self, state: &mut AppState) {
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                IndexingProgress::FileBatch(files) => {
                    // Append the batch directly into the in-memory index.
                    state.file_index.extend(files);
                }
                IndexingProgress::FileFound { count, .. } => {
                    state.indexing_status = IndexingStatus::Running { files_found: count };
                    state.status_message = format!("Indexing: {} files found…", count);
                }
                IndexingProgress::VolumeComplete { file_count, .. } => {
                    state.status_message = format!("Volume indexed: {} files", file_count);
                }
                IndexingProgress::Complete(stats) => {
                    state.indexing_status = IndexingStatus::Complete {
                        file_count: stats.file_count,
                    };
                    state.status_message = format!(
                        "Indexing complete: {} files in {}ms",
                        stats.file_count, stats.elapsed_ms
                    );
                }
                IndexingProgress::Failed(err) => {
                    state.indexing_status = IndexingStatus::Failed(err.clone());
                    state.error_message = Some(format!("Indexing failed: {}", err));
                }
            }
        }
    }
}
