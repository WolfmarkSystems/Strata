//! Resource profile for field laptops and workstations (FIELD-2).
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceProfile {
    pub max_ram_bytes: u64,
    pub max_threads: usize,
    pub use_mmap: bool,
    pub streaming_mode: bool,
    pub artifact_buffer_size: usize,
}

impl ResourceProfile {
    /// 16 GB+ RAM workstation.
    pub fn high_performance() -> Self {
        Self {
            max_ram_bytes: 16 * 1024 * 1024 * 1024,
            max_threads: default_threads().max(8),
            use_mmap: true,
            streaming_mode: false,
            artifact_buffer_size: 1_000_000,
        }
    }

    /// 8–16 GB RAM laptop.
    pub fn standard() -> Self {
        Self {
            max_ram_bytes: 4 * 1024 * 1024 * 1024,
            max_threads: default_threads().max(1),
            use_mmap: true,
            streaming_mode: false,
            artifact_buffer_size: 200_000,
        }
    }

    /// < 8 GB RAM field device.
    pub fn low_resource() -> Self {
        Self {
            max_ram_bytes: 1024 * 1024 * 1024,
            max_threads: (default_threads() / 2).max(1),
            use_mmap: false,
            streaming_mode: true,
            artifact_buffer_size: 10_000,
        }
    }

    /// Pick a profile from a caller-supplied available-RAM byte count.
    pub fn from_available_bytes(available: u64) -> Self {
        const GIB: u64 = 1024 * 1024 * 1024;
        if available >= 16 * GIB {
            Self::high_performance()
        } else if available >= 8 * GIB {
            Self::standard()
        } else {
            Self::low_resource()
        }
    }

    pub fn recommended_warning(available: u64) -> Option<String> {
        const GIB: u64 = 1024 * 1024 * 1024;
        if available < 8 * GIB {
            Some(format!(
                "LOW RESOURCE: {:.1} GB available — Strata will run in streaming mode.",
                available as f64 / GIB as f64
            ))
        } else {
            None
        }
    }
}

fn default_threads() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn high_performance_has_more_threads_than_low_resource() {
        let hp = ResourceProfile::high_performance();
        let lr = ResourceProfile::low_resource();
        assert!(hp.max_threads >= lr.max_threads);
        assert!(hp.artifact_buffer_size > lr.artifact_buffer_size);
        assert!(!hp.streaming_mode);
        assert!(lr.streaming_mode);
    }

    #[test]
    fn from_available_bytes_picks_correct_profile() {
        let gib = 1024 * 1024 * 1024;
        let hp = ResourceProfile::from_available_bytes(32 * gib);
        assert!(!hp.streaming_mode);
        let std_p = ResourceProfile::from_available_bytes(10 * gib);
        assert!(!std_p.streaming_mode);
        let lr = ResourceProfile::from_available_bytes(4 * gib);
        assert!(lr.streaming_mode);
    }

    #[test]
    fn recommended_warning_only_fires_below_threshold() {
        assert!(ResourceProfile::recommended_warning(32 * 1024 * 1024 * 1024).is_none());
        assert!(ResourceProfile::recommended_warning(4 * 1024 * 1024 * 1024).is_some());
    }

    #[test]
    fn low_resource_profile_enforces_streaming() {
        let lr = ResourceProfile::low_resource();
        assert!(lr.streaming_mode);
        assert!(lr.artifact_buffer_size <= 10_000);
        assert!(!lr.use_mmap);
    }
}
