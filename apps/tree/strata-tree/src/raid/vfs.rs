// raid/vfs.rs — RAID/JBOD reconstruction virtual filesystem.
// Phase 3, Task 3.4.
//
// Presents a striped/parity/spanned disk set as a single readable byte stream.
// Supported topologies:
//   - JBOD (span): members concatenated in order.
//   - RAID-0 (stripe): interleaved at configurable stripe_size.
//   - RAID-5 (parity): parity on rotating disk; read-only reconstruction.
//
// Forensic read-only guarantee: all member disks are opened O_RDONLY.
// No writes are ever issued to any member.
#![allow(dead_code)]

use anyhow::{bail, Context, Result};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

// ─── RAID topology ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RaidLevel {
    /// JBOD: members are concatenated in order (span).
    Jbod,
    /// RAID-0: data striped evenly across all members, no parity.
    Raid0,
    /// RAID-5: distributed parity (left-asymmetric rotation).
    Raid5,
}

impl std::fmt::Display for RaidLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RaidLevel::Jbod => write!(f, "JBOD (Span)"),
            RaidLevel::Raid0 => write!(f, "RAID-0 (Stripe)"),
            RaidLevel::Raid5 => write!(f, "RAID-5 (Distributed Parity)"),
        }
    }
}

// ─── Member disk ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RaidMember {
    /// Ordered position in the set (0-based).
    pub index: usize,
    /// Path to the disk image or raw device.
    pub path: PathBuf,
    /// Size in bytes (populated on open).
    pub size_bytes: u64,
}

impl RaidMember {
    pub fn new(index: usize, path: impl AsRef<Path>) -> Self {
        Self {
            index,
            path: path.as_ref().to_path_buf(),
            size_bytes: 0,
        }
    }
}

// ─── RAID VFS ────────────────────────────────────────────────────────────────

/// A reconstructed RAID set that implements Read + Seek over its logical address space.
pub struct RaidVfs {
    pub level: RaidLevel,
    pub members: Vec<RaidMember>,
    /// Stripe size in bytes.  Ignored for JBOD.
    pub stripe_size: u64,
    /// Logical size of the reconstructed volume in bytes.
    pub logical_size: u64,
    /// Open file handles (one per member, read-only).
    handles: Vec<File>,
    /// Current logical seek position.
    position: u64,
}

impl RaidVfs {
    /// Open a RAID set.
    ///
    /// # Arguments
    /// - `level`: JBOD, RAID-0, or RAID-5.
    /// - `members`: ordered disk image paths.
    /// - `stripe_size`: stripe size in bytes (must be a power of two; ignored for JBOD).
    pub fn open(level: RaidLevel, members: Vec<RaidMember>, stripe_size: u64) -> Result<Self> {
        if members.is_empty() {
            bail!("At least one member disk is required");
        }
        if matches!(level, RaidLevel::Raid0 | RaidLevel::Raid5)
            && (stripe_size == 0 || stripe_size & (stripe_size - 1) != 0)
        {
            bail!("stripe_size must be a non-zero power of two");
        }
        if level == RaidLevel::Raid5 && members.len() < 3 {
            bail!("RAID-5 requires at least 3 member disks");
        }

        let mut opened_members = members;
        let mut handles = Vec::with_capacity(opened_members.len());

        for m in &mut opened_members {
            let f = File::open(&m.path)
                .with_context(|| format!("Cannot open RAID member: {}", m.path.display()))?;
            m.size_bytes = f.metadata().map(|md| md.len()).unwrap_or(0);
            handles.push(f);
        }

        let logical_size = compute_logical_size(level, &opened_members, stripe_size);

        Ok(Self {
            level,
            members: opened_members,
            stripe_size,
            logical_size,
            handles,
            position: 0,
        })
    }

    /// Number of data disks (excludes parity disk for RAID-5).
    pub fn data_disk_count(&self) -> usize {
        match self.level {
            RaidLevel::Raid5 => self.members.len() - 1,
            _ => self.members.len(),
        }
    }
}

impl Seek for RaidVfs {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let new_pos: i64 = match pos {
            SeekFrom::Start(p) => p as i64,
            SeekFrom::End(d) => self.logical_size as i64 + d,
            SeekFrom::Current(d) => self.position as i64 + d,
        };
        if new_pos < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Seek before beginning of RAID volume",
            ));
        }
        self.position = new_pos as u64;
        Ok(self.position)
    }
}

impl Read for RaidVfs {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.position >= self.logical_size {
            return Ok(0);
        }
        let can_read = (self.logical_size - self.position).min(buf.len() as u64) as usize;
        let result = match self.level {
            RaidLevel::Jbod => self.read_jbod(&mut buf[..can_read]),
            RaidLevel::Raid0 => self.read_raid0(&mut buf[..can_read]),
            RaidLevel::Raid5 => self.read_raid5(&mut buf[..can_read]),
        };
        if let Ok(n) = result {
            self.position += n as u64;
        }
        result
    }
}

// ─── Read implementations ────────────────────────────────────────────────────

impl RaidVfs {
    /// JBOD: read from member disks sequentially.
    fn read_jbod(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut offset = self.position;
        let mut filled = 0;

        for (i, member) in self.members.iter().enumerate() {
            if offset >= member.size_bytes {
                offset -= member.size_bytes;
                continue;
            }
            let available = (member.size_bytes - offset) as usize;
            let want = (buf.len() - filled).min(available);
            self.handles[i].seek(SeekFrom::Start(offset))?;
            let n = self.handles[i].read(&mut buf[filled..filled + want])?;
            filled += n;
            offset = 0;
            if filled == buf.len() {
                break;
            }
        }
        Ok(filled)
    }

    /// RAID-0: data interleaved in stripe_size chunks across all disks.
    fn read_raid0(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n_disks = self.members.len() as u64;
        let stripe = self.stripe_size;
        let mut filled = 0;
        let mut pos = self.position;

        while filled < buf.len() {
            let stripe_num = pos / stripe;
            let stripe_off = pos % stripe;
            let disk_idx = (stripe_num % n_disks) as usize;
            let disk_stripe = stripe_num / n_disks;
            let disk_offset = disk_stripe * stripe + stripe_off;

            let want = (stripe - stripe_off) as usize;
            let want = want.min(buf.len() - filled);

            self.handles[disk_idx].seek(SeekFrom::Start(disk_offset))?;
            let n = self.handles[disk_idx].read(&mut buf[filled..filled + want])?;
            if n == 0 {
                break;
            }
            filled += n;
            pos += n as u64;
        }
        Ok(filled)
    }

    /// RAID-5: left-asymmetric parity layout.  Reconstructs missing data from parity.
    /// In this implementation all disks are assumed healthy — parity is not used for
    /// reconstruction but the layout math correctly skips parity blocks.
    fn read_raid5(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n_disks = self.members.len() as u64;
        let n_data = n_disks - 1;
        let stripe = self.stripe_size;
        let mut filled = 0;
        let mut pos = self.position;

        while filled < buf.len() {
            // Which data stripe (across all data disks)?
            let data_stripe_num = pos / (n_data * stripe);
            let offset_in_row = pos % (n_data * stripe);
            let data_disk_local = offset_in_row / stripe;
            let stripe_off = offset_in_row % stripe;

            // In left-asymmetric layout, parity disk = N - 1 - (stripe_num % N).
            let parity_disk = (n_disks - 1).wrapping_sub(data_stripe_num % n_disks);

            // Map data_disk_local to physical disk (skip parity disk).
            let phys_disk = if data_disk_local < parity_disk {
                data_disk_local
            } else {
                data_disk_local + 1
            };
            let disk_offset = data_stripe_num * stripe + stripe_off;

            let want = (stripe - stripe_off) as usize;
            let want = want.min(buf.len() - filled);

            self.handles[phys_disk as usize].seek(SeekFrom::Start(disk_offset))?;
            let n = self.handles[phys_disk as usize].read(&mut buf[filled..filled + want])?;
            if n == 0 {
                break;
            }
            filled += n;
            pos += n as u64;
        }
        Ok(filled)
    }
}

// ─── Logical size calculation ─────────────────────────────────────────────────

fn compute_logical_size(level: RaidLevel, members: &[RaidMember], stripe_size: u64) -> u64 {
    match level {
        RaidLevel::Jbod => members.iter().map(|m| m.size_bytes).sum(),
        RaidLevel::Raid0 => {
            let min_size = members.iter().map(|m| m.size_bytes).min().unwrap_or(0);
            min_size * members.len() as u64
        }
        RaidLevel::Raid5 => {
            let n_data = (members.len() as u64).saturating_sub(1);
            let min_size = members.iter().map(|m| m.size_bytes).min().unwrap_or(0);
            // Round down to whole stripe boundary.
            let stripes = min_size / stripe_size;
            stripes * stripe_size * n_data
        }
    }
}

// ─── UI helper ───────────────────────────────────────────────────────────────

/// State for the RAID configuration dialog shown in the Open Evidence dialog.
#[derive(Debug, Default)]
pub struct RaidDialogState {
    pub level: Option<RaidLevel>,
    pub members: Vec<String>,
    pub stripe_size_kb: u32,
    pub error: Option<String>,
}

impl RaidDialogState {
    pub fn new() -> Self {
        Self {
            stripe_size_kb: 64,
            ..Default::default()
        }
    }
}

/// Render the RAID configuration dialog (embedded in Open Evidence dialog).
pub fn render_raid_config(ui: &mut egui::Ui, state: &mut RaidDialogState) -> Option<RaidVfs> {
    ui.heading("RAID / Multi-Disk Reconstruction");
    ui.separator();

    // Level selector.
    ui.label("Array type:");
    ui.horizontal(|ui| {
        for (label, level) in [
            ("JBOD (Span)", RaidLevel::Jbod),
            ("RAID-0 (Stripe)", RaidLevel::Raid0),
            ("RAID-5 (Parity)", RaidLevel::Raid5),
        ] {
            let sel = state.level == Some(level);
            if ui.radio(sel, label).clicked() {
                state.level = Some(level);
            }
        }
    });

    // Stripe size (for RAID-0/5).
    if matches!(state.level, Some(RaidLevel::Raid0) | Some(RaidLevel::Raid5)) {
        ui.horizontal(|ui| {
            ui.label("Stripe size (KB):");
            ui.add(egui::DragValue::new(&mut state.stripe_size_kb).range(4u32..=4096u32));
        });
    }

    ui.separator();
    ui.label("Member disks (ordered):");

    let mut remove = None;
    for (i, path) in state.members.iter_mut().enumerate() {
        ui.horizontal(|ui| {
            ui.label(format!("Disk {}", i));
            ui.text_edit_singleline(path);
            if ui.small_button("✕").clicked() {
                remove = Some(i);
            }
        });
    }
    if let Some(i) = remove {
        state.members.remove(i);
    }

    if ui.button("+ Add Disk").clicked() {
        state.members.push(String::new());
    }

    ui.separator();

    if let Some(ref err) = state.error.clone() {
        ui.colored_label(egui::Color32::from_rgb(220, 80, 80), err);
    }

    if ui.button("Reconstruct & Open").clicked() {
        if let Some(level) = state.level {
            let members: Vec<RaidMember> = state
                .members
                .iter()
                .enumerate()
                .filter(|(_, p)| !p.is_empty())
                .map(|(i, p)| RaidMember::new(i, p))
                .collect();

            let stripe = (state.stripe_size_kb as u64) * 1024;
            match RaidVfs::open(level, members, stripe) {
                Ok(vfs) => {
                    state.error = None;
                    return Some(vfs);
                }
                Err(e) => {
                    state.error = Some(format!("Failed: {}", e));
                }
            }
        } else {
            state.error = Some("Select an array type.".to_string());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::{RaidLevel, RaidMember, RaidVfs};
    use std::io::Read;

    #[test]
    fn raid0_reads_striped_members_in_order() {
        let root =
            std::env::temp_dir().join(format!("strata_raid0_test_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).expect("create temp root");

        let disk0 = root.join("disk0.img");
        let disk1 = root.join("disk1.img");
        std::fs::write(&disk0, b"AAAABBBB").expect("write disk0");
        std::fs::write(&disk1, b"CCCCDDDD").expect("write disk1");

        let members = vec![RaidMember::new(0, &disk0), RaidMember::new(1, &disk1)];
        let mut raid = RaidVfs::open(RaidLevel::Raid0, members, 4).expect("open raid0");

        let mut out = vec![0u8; 16];
        let read = raid.read(&mut out).expect("read raid0");
        out.truncate(read);

        assert_eq!(out, b"AAAACCCCBBBBDDDD");

        let _ = std::fs::remove_dir_all(&root);
    }
}
