use crate::audit::event::AuditEventType;
use crate::audit::logger::AuditLogger;
use crate::container::EvidenceContainerRO;

use std::sync::Arc;
use uuid::Uuid;

const ATTR_STANDARD_INFORMATION: u32 = 0x10;
const ATTR_FILE_NAME: u32 = 0x30;
const ATTR_DATA: u32 = 0x80;
const ATTR_INDEX_ROOT: u32 = 0x90;
const ATTR_INDEX_ALLOCATION: u32 = 0xA0;

/// Result of NTFS fast scan (boot sector + $MFT record 0 only).
#[derive(Debug, Clone)]
pub struct NtfsFastScanResult {
    pub boot: NtfsBootSector,
    pub mft0_offset: u64,
    pub record_size: u32,
    pub mft0: NtfsFileRecordSummary,
    pub bitmap: Vec<u8>,
}

/// Parsed NTFS boot sector fields used for fast scan.
#[derive(Debug, Clone)]
pub struct NtfsBootSector {
    pub oem_id: [u8; 8],
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub total_sectors: u64,
    pub mft_lcn: i64,
    pub mftmirr_lcn: i64,
    pub mft_record_size_bytes: u32,
    pub serial_number: u64,
    pub cluster_size_bytes: u32,
}

/// Minimal summary of an MFT FILE record header.
#[derive(Debug, Clone)]
pub struct NtfsFileRecordSummary {
    pub sequence_number: u16,
    pub hard_link_count: u16,
    pub first_attribute_offset: u16,
    pub flags: u16,
    pub used_size: u32,
    pub allocated_size: u32,
    pub base_record_reference: u64,
    pub next_attribute_id: u16,
    pub record_number: u32,
}

#[derive(Debug)]
pub enum NtfsScanError {
    NotNtfs(&'static str),
    InvalidBootSector(&'static str),
    InvalidFileRecord(&'static str),
    UsaFixupFailed(&'static str),
    OutOfRange(&'static str),
}

impl std::fmt::Display for NtfsScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NtfsScanError::NotNtfs(m) => write!(f, "Not NTFS: {m}"),
            NtfsScanError::InvalidBootSector(m) => write!(f, "Invalid NTFS boot sector: {m}"),
            NtfsScanError::InvalidFileRecord(m) => write!(f, "Invalid NTFS FILE record: {m}"),
            NtfsScanError::UsaFixupFailed(m) => write!(f, "NTFS USA fixup failed: {m}"),
            NtfsScanError::OutOfRange(m) => write!(f, "NTFS scan out of range: {m}"),
        }
    }
}

impl std::error::Error for NtfsScanError {}

/// NTFS fast scan (metadata only), partition-aware:
/// - read VBR at `base_offset`
/// - parse boot sector
/// - compute $MFT[0] byte offset = base_offset + (mft_lcn * cluster_size)
/// - read exactly one MFT record (record 0)
/// - validate signature + apply USA fixups
/// - parse header summary
pub fn ntfs_fast_scan<C: EvidenceContainerRO>(
    container: &C,
    base_offset: u64,
    case_id: Uuid,
    audit: Arc<AuditLogger>,
) -> Result<NtfsFastScanResult, NtfsScanError> {
    let sector_size = container.sector_size();

    // VBR read length: one sector (or remaining bytes if near EOF)
    let max_len = container.size().saturating_sub(base_offset);
    let read_len = sector_size.min(max_len);

    if read_len == 0 {
        audit.log(
            case_id,
            AuditEventType::Error {
                message: "NTFS fast scan: base_offset beyond EOF".to_string(),
            },
        );
        return Err(NtfsScanError::InvalidBootSector("base_offset beyond EOF"));
    }

    let vbr = container
        .read_at(base_offset, read_len)
        .map_err(|_| NtfsScanError::InvalidBootSector("failed to read VBR"))?;

    let boot = parse_boot_sector(&vbr, &audit, case_id)?;

    // Capture record size BEFORE moving `boot` into result (fixes your E0382 move error)
    let record_size = boot.mft_record_size_bytes;
    let rec_len = record_size as u64;

    if rec_len == 0 || rec_len > 1024 * 1024 {
        audit.log(
            case_id,
            AuditEventType::Error {
                message: format!("NTFS fast scan: unreasonable MFT record size: {}", rec_len),
            },
        );
        return Err(NtfsScanError::InvalidBootSector(
            "unreasonable MFT record size",
        ));
    }

    // Compute $MFT[0] offset relative to the *volume base*
    let mft0_rel = lcn_to_offset(boot.mft_lcn, boot.cluster_size_bytes, &audit, case_id)?;
    let mft0_offset = base_offset
        .checked_add(mft0_rel)
        .ok_or(NtfsScanError::OutOfRange("MFT offset overflow"))?;

    // Read MFT record 0
    let mut mft0 = container
        .read_at(mft0_offset, rec_len)
        .map_err(|_| NtfsScanError::InvalidFileRecord("failed to read $MFT record 0"))?;

    validate_file_signature(&mft0)?;
    apply_usa_fixup(&mut mft0, boot.bytes_per_sector)?;

    let mft0_summary = parse_file_record_header(&mft0)?;

    let bitmap = read_ntfs_bitmap(container, &boot, base_offset).unwrap_or_default();

    Ok(NtfsFastScanResult {
        boot,
        mft0_offset,
        record_size,
        mft0: mft0_summary,
        bitmap,
    })
}

fn read_ntfs_bitmap<C: EvidenceContainerRO>(
    container: &C,
    boot: &NtfsBootSector,
    volume_offset: u64,
) -> Result<Vec<u8>, NtfsScanError> {
    let cluster_size = boot.cluster_size_bytes as u64;
    let total_clusters = boot.total_sectors / boot.sectors_per_cluster as u64;
    let bitmap_size = total_clusters.div_ceil(8) as usize;

    let mft_lcn = boot.mft_lcn;
    if mft_lcn < 0 {
        return Ok(Vec::new());
    }

    let bitmap_file_offset = lcn_to_offset(
        mft_lcn,
        boot.cluster_size_bytes,
        &AuditLogger::new(),
        Uuid::nil(),
    )
    .map_err(|_| NtfsScanError::InvalidFileRecord("failed to compute bitmap offset"))?;

    let bitmap_cluster = (bitmap_file_offset / cluster_size) as u64;
    let bitmap_offset = volume_offset + (bitmap_cluster * cluster_size);

    let max_read = container.size().saturating_sub(bitmap_offset);
    if max_read == 0 || max_read > 10 * 1024 * 1024 {
        return Ok(Vec::new());
    }

    let read_size = (bitmap_size as u64).min(max_read).min(10 * 1024 * 1024) as usize;

    match container.read_at(bitmap_offset, read_size as u64) {
        Ok(data) => {
            if data.len() >= bitmap_size {
                Ok(data[..bitmap_size].to_vec())
            } else {
                Ok(data)
            }
        }
        Err(_) => Ok(Vec::new()),
    }
}

fn lcn_to_offset(
    lcn: i64,
    cluster_size_bytes: u32,
    audit: &AuditLogger,
    case_id: Uuid,
) -> Result<u64, NtfsScanError> {
    let off = (lcn as i128)
        .checked_mul(cluster_size_bytes as i128)
        .ok_or(NtfsScanError::OutOfRange("LCN->offset overflow"))?;

    if off < 0 {
        audit.log(
            case_id,
            AuditEventType::Error {
                message: "NTFS fast scan: negative LCN offset".to_string(),
            },
        );
        return Err(NtfsScanError::OutOfRange("negative LCN offset"));
    }

    Ok(off as u64)
}

fn parse_boot_sector(
    vbr: &[u8],
    audit: &AuditLogger,
    case_id: Uuid,
) -> Result<NtfsBootSector, NtfsScanError> {
    if vbr.len() < 90 {
        audit.log(
            case_id,
            AuditEventType::Error {
                message: "NTFS boot sector too small".to_string(),
            },
        );
        return Err(NtfsScanError::InvalidBootSector("VBR too small"));
    }

    // OEM ID should be "NTFS    "
    let mut oem_id = [0u8; 8];
    oem_id.copy_from_slice(&vbr[3..11]);
    if &oem_id != b"NTFS    " {
        return Err(NtfsScanError::NotNtfs("OEM ID is not NTFS"));
    }

    let bytes_per_sector = u16::from_le_bytes([vbr[0x0B], vbr[0x0C]]);
    let sectors_per_cluster = vbr[0x0D];

    if !matches!(bytes_per_sector, 512 | 1024 | 2048 | 4096) {
        return Err(NtfsScanError::InvalidBootSector(
            "unexpected bytes_per_sector",
        ));
    }
    if sectors_per_cluster == 0 {
        return Err(NtfsScanError::InvalidBootSector(
            "sectors_per_cluster is zero",
        ));
    }

    let cluster_size_bytes = (bytes_per_sector as u32)
        .checked_mul(sectors_per_cluster as u32)
        .ok_or(NtfsScanError::InvalidBootSector("cluster size overflow"))?;

    let total_sectors = u64::from_le_bytes([
        vbr[0x28], vbr[0x29], vbr[0x2A], vbr[0x2B], vbr[0x2C], vbr[0x2D], vbr[0x2E], vbr[0x2F],
    ]);

    let mft_lcn = i64::from_le_bytes([
        vbr[0x30], vbr[0x31], vbr[0x32], vbr[0x33], vbr[0x34], vbr[0x35], vbr[0x36], vbr[0x37],
    ]);

    let mftmirr_lcn = i64::from_le_bytes([
        vbr[0x38], vbr[0x39], vbr[0x3A], vbr[0x3B], vbr[0x3C], vbr[0x3D], vbr[0x3E], vbr[0x3F],
    ]);

    // clusters_per_mft_record is signed int8
    let clusters_per_mft_record = vbr[0x40] as i8;
    let mft_record_size_bytes = if clusters_per_mft_record > 0 {
        (clusters_per_mft_record as u32)
            .checked_mul(cluster_size_bytes)
            .ok_or(NtfsScanError::InvalidBootSector("MFT record size overflow"))?
    } else {
        let shift = (-clusters_per_mft_record) as u32;
        if shift > 30 {
            return Err(NtfsScanError::InvalidBootSector(
                "MFT record size shift too large",
            ));
        }
        1u32 << shift
    };

    if !(512..=1024 * 1024).contains(&mft_record_size_bytes) {
        return Err(NtfsScanError::InvalidBootSector(
            "unreasonable MFT record size",
        ));
    }

    let serial_number = u64::from_le_bytes([
        vbr[0x48], vbr[0x49], vbr[0x4A], vbr[0x4B], vbr[0x4C], vbr[0x4D], vbr[0x4E], vbr[0x4F],
    ]);

    Ok(NtfsBootSector {
        oem_id,
        bytes_per_sector,
        sectors_per_cluster,
        total_sectors,
        mft_lcn,
        mftmirr_lcn,
        mft_record_size_bytes,
        serial_number,
        cluster_size_bytes,
    })
}

fn validate_file_signature(rec: &[u8]) -> Result<(), NtfsScanError> {
    if rec.len() < 4 {
        return Err(NtfsScanError::InvalidFileRecord("record too small"));
    }
    if rec[0..4] != b"FILE"[..] {
        return Err(NtfsScanError::InvalidFileRecord("missing FILE signature"));
    }
    Ok(())
}

/// Apply USA fixups (torn-write detection).
fn apply_usa_fixup(rec: &mut [u8], bytes_per_sector: u16) -> Result<(), NtfsScanError> {
    if rec.len() < 8 {
        return Err(NtfsScanError::UsaFixupFailed(
            "record too small for USA header",
        ));
    }

    let usa_offset = u16::from_le_bytes([rec[0x04], rec[0x05]]) as usize;
    let usa_count = u16::from_le_bytes([rec[0x06], rec[0x07]]) as usize;

    if usa_offset == 0 || usa_count < 2 {
        return Err(NtfsScanError::UsaFixupFailed("invalid USA offset/count"));
    }

    let usa_bytes = usa_count
        .checked_mul(2)
        .ok_or(NtfsScanError::UsaFixupFailed("USA size overflow"))?;
    if usa_offset + usa_bytes > rec.len() {
        return Err(NtfsScanError::UsaFixupFailed("USA array out of bounds"));
    }

    let bps = bytes_per_sector as usize;
    if !(256..=4096).contains(&bps) || (bps & (bps - 1)) != 0 {
        return Err(NtfsScanError::UsaFixupFailed("invalid bytes_per_sector"));
    }
    if !rec.len().is_multiple_of(bps) {
        return Err(NtfsScanError::UsaFixupFailed(
            "record size is not a multiple of bytes_per_sector",
        ));
    }

    let sector_count = rec.len() / bps;
    if usa_count != sector_count + 1 {
        return Err(NtfsScanError::UsaFixupFailed(
            "USA count does not match sector count",
        ));
    }

    let usn = [rec[usa_offset], rec[usa_offset + 1]];

    for i in 0..sector_count {
        let trailer_pos = (i + 1) * bps - 2;

        if rec[trailer_pos] != usn[0] || rec[trailer_pos + 1] != usn[1] {
            return Err(NtfsScanError::UsaFixupFailed(
                "sector trailer does not match USN (torn/corrupt record)",
            ));
        }

        let fix_pos = usa_offset + 2 * (i + 1);
        rec[trailer_pos] = rec[fix_pos];
        rec[trailer_pos + 1] = rec[fix_pos + 1];
    }

    Ok(())
}

fn parse_file_record_header(rec: &[u8]) -> Result<NtfsFileRecordSummary, NtfsScanError> {
    if rec.len() < 0x30 {
        return Err(NtfsScanError::InvalidFileRecord(
            "record too small for header parse",
        ));
    }

    let sequence_number = u16::from_le_bytes([rec[0x10], rec[0x11]]);
    let hard_link_count = u16::from_le_bytes([rec[0x12], rec[0x13]]);
    let first_attribute_offset = u16::from_le_bytes([rec[0x14], rec[0x15]]);
    let flags = u16::from_le_bytes([rec[0x16], rec[0x17]]);
    let used_size = u32::from_le_bytes([rec[0x18], rec[0x19], rec[0x1A], rec[0x1B]]);
    let allocated_size = u32::from_le_bytes([rec[0x1C], rec[0x1D], rec[0x1E], rec[0x1F]]);
    let base_record_reference = u64::from_le_bytes([
        rec[0x20], rec[0x21], rec[0x22], rec[0x23], rec[0x24], rec[0x25], rec[0x26], rec[0x27],
    ]);
    let next_attribute_id = u16::from_le_bytes([rec[0x28], rec[0x29]]);
    let record_number = u32::from_le_bytes([rec[0x2C], rec[0x2D], rec[0x2E], rec[0x2F]]);

    if (first_attribute_offset as usize) >= rec.len() {
        return Err(NtfsScanError::InvalidFileRecord(
            "first_attribute_offset out of bounds",
        ));
    }

    Ok(NtfsFileRecordSummary {
        sequence_number,
        hard_link_count,
        first_attribute_offset,
        flags,
        used_size,
        allocated_size,
        base_record_reference,
        next_attribute_id,
        record_number,
    })
}

#[derive(Debug, Clone)]
pub struct NtfsFileEntry {
    pub record_number: u32,
    pub sequence_number: u16,
    pub flags: u16,
    pub name: Option<String>,
    pub size: u64,
    pub created: Option<i64>,
    pub modified: Option<i64>,
    pub accessed: Option<i64>,
    pub mft_modified: Option<i64>,
    pub is_directory: bool,
}

impl NtfsFileEntry {
    pub fn timestamp(&self) -> Option<i64> {
        self.modified
            .or(self.created)
            .or(self.accessed)
            .or(self.mft_modified)
    }
}

#[derive(Debug, Clone)]
pub struct NtfsMftEnumerator {
    mft_start_offset: u64,
    record_size: u32,
    cluster_size: u32,
    max_records: u32,
}

impl NtfsMftEnumerator {
    pub fn new(
        mft_start_offset: u64,
        record_size: u32,
        cluster_size: u32,
        max_records: u32,
    ) -> Self {
        Self {
            mft_start_offset,
            record_size,
            cluster_size,
            max_records,
        }
    }

    pub fn read_record<C: EvidenceContainerRO>(
        &self,
        container: &C,
        record_number: u32,
    ) -> Result<NtfsFileEntry, NtfsScanError> {
        if record_number >= self.max_records {
            return Err(NtfsScanError::OutOfRange("record number exceeds MFT size"));
        }

        let offset = self.mft_start_offset + (record_number as u64) * (self.record_size as u64);
        let rec_len = self.record_size as u64;

        if offset + rec_len > container.size() {
            return Err(NtfsScanError::OutOfRange("MFT record beyond EOF"));
        }

        let mut data = container
            .read_at(offset, rec_len)
            .map_err(|_| NtfsScanError::InvalidFileRecord("failed to read MFT record"))?;

        validate_file_signature(&data)?;
        apply_usa_fixup(&mut data, self.cluster_size as u16)?;

        parse_mft_record(&data, record_number)
    }
}

fn parse_mft_record(data: &[u8], record_number: u32) -> Result<NtfsFileEntry, NtfsScanError> {
    if data.len() < 0x30 {
        return Err(NtfsScanError::InvalidFileRecord("record too small"));
    }

    let sequence_number = u16::from_le_bytes([data[0x10], data[0x11]]);
    let flags = u16::from_le_bytes([data[0x16], data[0x17]]);
    let is_directory = (flags & 0x01) != 0;

    let first_attr_offset = u16::from_le_bytes([data[0x14], data[0x15]]) as usize;
    let mut pos = first_attr_offset;

    let mut name: Option<String> = None;
    let mut created: Option<i64> = None;
    let mut modified: Option<i64> = None;
    let mut accessed: Option<i64> = None;
    let mut mft_modified: Option<i64> = None;
    let mut size: u64 = 0;

    while pos + 8 <= data.len() {
        let attr_type =
            u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        let attr_len =
            u32::from_le_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);

        if attr_len == 0 {
            break;
        }

        if pos + (attr_len as usize) > data.len() {
            break;
        }

        match attr_type {
            ATTR_STANDARD_INFORMATION => {
                if attr_len >= 48 {
                    created = Some(i64::from_le_bytes([
                        data[pos + 8],
                        data[pos + 9],
                        data[pos + 10],
                        data[pos + 11],
                        data[pos + 12],
                        data[pos + 13],
                        data[pos + 14],
                        data[pos + 15],
                    ]));
                    modified = Some(i64::from_le_bytes([
                        data[pos + 16],
                        data[pos + 17],
                        data[pos + 18],
                        data[pos + 19],
                        data[pos + 20],
                        data[pos + 21],
                        data[pos + 22],
                        data[pos + 23],
                    ]));
                    mft_modified = Some(i64::from_le_bytes([
                        data[pos + 24],
                        data[pos + 25],
                        data[pos + 26],
                        data[pos + 27],
                        data[pos + 28],
                        data[pos + 29],
                        data[pos + 30],
                        data[pos + 31],
                    ]));
                    accessed = Some(i64::from_le_bytes([
                        data[pos + 32],
                        data[pos + 33],
                        data[pos + 34],
                        data[pos + 35],
                        data[pos + 36],
                        data[pos + 37],
                        data[pos + 38],
                        data[pos + 39],
                    ]));
                }
            }
            ATTR_FILE_NAME => {
                if attr_len >= 66 {
                    let name_len = data[pos + 64] as usize;
                    if name_len > 0 && name_len < 256 && (attr_len as usize) >= 66 + (name_len * 2)
                    {
                        let start = pos + 66;
                        let end = start + (name_len * 2);
                        if end > data.len() {
                            break;
                        }
                        let name_bytes = &data[start..end];
                        let name_str = u16_slice_to_string(name_bytes);
                        if !name_str.is_empty() {
                            name = Some(name_str);
                        }
                    }
                }
            }
            ATTR_DATA => {
                if !is_directory && attr_len >= 16 {
                    size = u64::from_le_bytes([
                        data[pos + 16],
                        data[pos + 17],
                        data[pos + 18],
                        data[pos + 19],
                        data[pos + 20],
                        data[pos + 21],
                        data[pos + 22],
                        data[pos + 23],
                    ]);
                }
            }
            _ => {}
        }

        pos += attr_len as usize;
    }

    let entry = NtfsFileEntry {
        record_number,
        sequence_number,
        flags,
        name,
        size,
        created,
        modified,
        accessed,
        mft_modified,
        is_directory,
    };

    tracing::debug!(
        "[MFT] rec={} name={:?} created={:?} modified={:?} accessed={:?} mft_changed={:?}",
        entry.record_number,
        entry.name,
        entry.created,
        entry.modified,
        entry.accessed,
        entry.mft_modified
    );

    Ok(entry)
}

fn u16_slice_to_string(slice: &[u8]) -> String {
    let mut chars = Vec::new();
    for chunk in slice.chunks(2) {
        if chunk.len() == 2 {
            let c = u16::from_le_bytes([chunk[0], chunk[1]]);
            if c == 0 {
                break;
            }
            if let Some(c) = char::from_u32(c as u32) {
                chars.push(c);
            }
        }
    }
    chars.into_iter().collect()
}

pub fn enumerate_mft<C: EvidenceContainerRO>(
    container: &C,
    volume_base_offset: u64,
    max_records: u32,
    _case_id: Uuid,
    _audit: Arc<AuditLogger>,
) -> Result<Vec<NtfsFileEntry>, ForensicError> {
    #[cfg(feature = "parallel")]
    {
        enumerate_mft_parallel(container, volume_base_offset, max_records)
    }
    #[cfg(not(feature = "parallel"))]
    {
        enumerate_mft_sequential(container, volume_base_offset, max_records)
    }
}

#[cfg(feature = "parallel")]
fn enumerate_mft_parallel<C: EvidenceContainerRO>(
    container: &C,
    volume_base_offset: u64,
    max_records: u32,
) -> Result<Vec<NtfsFileEntry>, ForensicError> {
    use rayon::prelude::*;

    let sector_size = container.sector_size();
    let max_len = container.size().saturating_sub(volume_base_offset);
    let read_len = sector_size.min(max_len);

    if read_len == 0 {
        return Err(ForensicError::InvalidImageFormat);
    }

    let vbr = container.read_at(volume_base_offset, read_len)?;
    let boot = parse_boot_sector_internal(&vbr)?;

    let record_size = if boot.clusters_per_mft_record > 0 {
        (boot.clusters_per_mft_record as u32) * boot.cluster_size_bytes
    } else {
        1u32 << (-boot.clusters_per_mft_record as i32)
    };

    let mft0_rel = (boot.mft_lcn as u64) * (boot.cluster_size_bytes as u64);
    let mft_offset = volume_base_offset + mft0_rel;

    let max_scan = max_records.clamp(1, 100000);

    const BULK_READ_SIZE: u64 = 1024 * 1024;
    // const CHUNK_SIZE: usize = 1024;

    let num_bulk_reads = ((max_scan as u64 * record_size as u64) / BULK_READ_SIZE).max(1) as usize;

    let mut all_entries: Vec<NtfsFileEntry> = Vec::with_capacity(max_scan as usize);
    let bytes_per_sector = boot.bytes_per_sector as usize;

    for bulk_idx in 0..num_bulk_reads {
        let bulk_offset = mft_offset + (bulk_idx as u64 * BULK_READ_SIZE);
        let bulk_end =
            (bulk_offset + BULK_READ_SIZE).min(mft_offset + (max_scan as u64 * record_size as u64));
        let bulk_len = (bulk_end - bulk_offset) as usize;

        if bulk_len == 0 {
            continue;
        }

        let bulk_data = match container.read_at(bulk_offset, bulk_len as u64) {
            Ok(d) => d,
            Err(_) => continue,
        };

        let record_count = bulk_data.len() / record_size as usize;

        let entries: Vec<Option<NtfsFileEntry>> = (0..record_count)
            .into_par_iter()
            .with_max_len(256)
            .map(|i| {
                let offset = i * record_size as usize;
                if offset + record_size as usize > bulk_data.len() {
                    return None;
                }

                let mut record = bulk_data[offset..offset + record_size as usize].to_vec();
                if record.len() < 4 || &record[0..4] != b"FILE" {
                    return None;
                }

                if apply_usa_fixup(&mut record, bytes_per_sector as u16).is_err() {
                    return None;
                }

                parse_mft_record(
                    &record,
                    (bulk_idx * BULK_READ_SIZE as usize / record_size as usize + i) as u32,
                )
                .ok()
            })
            .collect();

        for e in entries.into_iter().flatten() {
            all_entries.push(e);
        }
    }

    tracing::info!(
        "[MFT] Parallel enumeration: {} entries from {} records",
        all_entries.len(),
        max_scan
    );
    Ok(all_entries)
}

#[cfg(not(feature = "parallel"))]
fn enumerate_mft_sequential<C: EvidenceContainerRO>(
    container: &C,
    volume_base_offset: u64,
    max_records: u32,
) -> Result<Vec<NtfsFileEntry>, ForensicError> {
    let sector_size = container.sector_size();
    let max_len = container.size().saturating_sub(volume_base_offset);
    let read_len = sector_size.min(max_len);

    if read_len == 0 {
        return Err(ForensicError::InvalidImageFormat);
    }

    let vbr = container.read_at(volume_base_offset, read_len)?;

    let boot = parse_boot_sector_internal(&vbr)?;

    let record_size = if boot.clusters_per_mft_record > 0 {
        (boot.clusters_per_mft_record as u32) * boot.cluster_size_bytes
    } else {
        1u32 << (-boot.clusters_per_mft_record as i32)
    };

    let mft0_rel = (boot.mft_lcn as u64) * (boot.cluster_size_bytes as u64);
    let mft_offset = volume_base_offset + mft0_rel;

    const BULK_READ_SIZE: u64 = 512 * 1024;
    let max_scan = max_records.min(10000).max(1);
    let bytes_per_sector = boot.bytes_per_sector as usize;

    let mut entries = Vec::with_capacity(max_scan as usize);
    let mut processed = 0u32;

    while processed < max_scan {
        let bulk_offset = mft_offset + (processed as u64 * record_size as u64);
        let remaining = (max_scan - processed).min((BULK_READ_SIZE / record_size as u64) as u32);
        let bulk_len = (remaining as u64 * record_size as u64) as usize;

        let bulk_data = match container.read_at(bulk_offset, bulk_len as u64) {
            Ok(d) => d,
            Err(_) => break,
        };

        let record_count = bulk_data.len() / record_size as usize;

        for i in 0..record_count {
            let offset = i * record_size as usize;
            if offset + record_size as usize > bulk_data.len() {
                break;
            }

            let mut record = bulk_data[offset..offset + record_size as usize].to_vec();
            if record.len() < 4 || &record[0..4] != b"FILE" {
                continue;
            }

            if apply_usa_fixup(&mut record, bytes_per_sector as u16).is_err() {
                continue;
            }

            match parse_mft_record(&record, processed + i as u32) {
                Ok(entry) => entries.push(entry),
                Err(_) => continue,
            }
        }

        processed += record_count as u32;
    }

    tracing::info!(
        "[MFT] Sequential enumeration: {} entries from {} records",
        entries.len(),
        processed
    );
    Ok(entries)
}

struct NtfsBootSectorInternal {
    bytes_per_sector: u16,
    cluster_size_bytes: u32,
    mft_lcn: i64,
    clusters_per_mft_record: i8,
}

fn parse_boot_sector_internal(vbr: &[u8]) -> Result<NtfsBootSectorInternal, ForensicError> {
    if vbr.len() < 90 || &vbr[3..11] != b"NTFS    " {
        return Err(ForensicError::UnsupportedFilesystem);
    }

    let bytes_per_sector = u16::from_le_bytes([vbr[0x0B], vbr[0x0C]]);
    let sectors_per_cluster = vbr[0x0D];
    let cluster_size_bytes = (bytes_per_sector as u32) * (sectors_per_cluster as u32);
    let mft_lcn = i64::from_le_bytes([
        vbr[0x30], vbr[0x31], vbr[0x32], vbr[0x33], vbr[0x34], vbr[0x35], vbr[0x36], vbr[0x37],
    ]);
    let clusters_per_mft_record = vbr[0x40] as i8;

    Ok(NtfsBootSectorInternal {
        bytes_per_sector,
        cluster_size_bytes,
        mft_lcn,
        clusters_per_mft_record,
    })
}

use crate::errors::ForensicError;

#[derive(Debug, Clone)]
pub struct TimelineEntry {
    pub timestamp: i64,
    pub action: String,
    pub path: String,
    pub size: Option<u64>,
    pub record_number: u32,
}

#[derive(Debug, Clone)]
pub struct NtfsDirectoryEntry {
    pub record_number: u32,
    pub sequence_number: u16,
    pub name: String,
    pub is_directory: bool,
    pub size: u64,
    pub created: Option<i64>,
    pub modified: Option<i64>,
    pub accessed: Option<i64>,
}

pub fn enumerate_directory<C: EvidenceContainerRO>(
    container: &C,
    volume_base_offset: u64,
    dir_record_number: u32,
    max_entries: u32,
) -> Result<Vec<NtfsDirectoryEntry>, ForensicError> {
    let sector_size = container.sector_size();
    let max_len = container.size().saturating_sub(volume_base_offset);
    let read_len = sector_size.min(max_len);

    if read_len == 0 {
        return Err(ForensicError::InvalidImageFormat);
    }

    let vbr = container.read_at(volume_base_offset, read_len)?;

    let boot = parse_boot_sector_internal(&vbr)?;

    let record_size = if boot.clusters_per_mft_record > 0 {
        (boot.clusters_per_mft_record as u32) * boot.cluster_size_bytes
    } else {
        1u32 << (-boot.clusters_per_mft_record as i32)
    };

    let mft0_rel = (boot.mft_lcn as u64) * (boot.cluster_size_bytes as u64);
    let mft_offset = volume_base_offset + mft0_rel;
    let dir_offset = mft_offset + (dir_record_number as u64) * (record_size as u64);

    if dir_offset + (record_size as u64) > container.size() {
        return Err(ForensicError::InvalidImageFormat);
    }

    let mut dir_data = container.read_at(dir_offset, record_size as u64)?;

    validate_file_signature(&dir_data).map_err(|_| ForensicError::InvalidImageFormat)?;
    apply_usa_fixup(&mut dir_data, boot.bytes_per_sector as u16)
        .map_err(|_| ForensicError::InvalidImageFormat)?;

    let first_attr_offset = u16::from_le_bytes([dir_data[0x14], dir_data[0x15]]) as usize;
    let mut pos = first_attr_offset;

    let mut index_root_range: Option<(usize, usize)> = None;
    let mut index_allocation_runs: Vec<(u64, u64)> = Vec::new();

    while pos + 8 <= dir_data.len() {
        let attr_type = u32::from_le_bytes([
            dir_data[pos],
            dir_data[pos + 1],
            dir_data[pos + 2],
            dir_data[pos + 3],
        ]);
        let attr_len = u32::from_le_bytes([
            dir_data[pos + 4],
            dir_data[pos + 5],
            dir_data[pos + 6],
            dir_data[pos + 7],
        ]);

        if attr_len == 0 {
            break;
        }

        if pos + (attr_len as usize) > dir_data.len() {
            break;
        }

        match attr_type {
            ATTR_INDEX_ROOT => {
                if attr_len >= 0x20 && dir_data[pos + 8] == 0 {
                    let value_len = u32::from_le_bytes([
                        dir_data[pos + 0x10],
                        dir_data[pos + 0x11],
                        dir_data[pos + 0x12],
                        dir_data[pos + 0x13],
                    ]) as usize;
                    let value_off =
                        u16::from_le_bytes([dir_data[pos + 0x14], dir_data[pos + 0x15]]) as usize;
                    let value_start = pos.saturating_add(value_off);
                    let value_end = value_start.saturating_add(value_len);
                    if value_start < dir_data.len() && value_end <= dir_data.len() {
                        index_root_range = Some((value_start, value_end));
                    }
                }
            }
            ATTR_INDEX_ALLOCATION => {
                if attr_len >= 0x40 && dir_data[pos + 8] != 0 {
                    let runlist_off =
                        u16::from_le_bytes([dir_data[pos + 0x20], dir_data[pos + 0x21]]) as usize;
                    if runlist_off > 0 && runlist_off < attr_len as usize {
                        let runlist_start = pos + runlist_off;
                        let runlist_end = pos + attr_len as usize;
                        if runlist_end <= dir_data.len() && runlist_start < runlist_end {
                            index_allocation_runs =
                                parse_data_runs(&dir_data[runlist_start..runlist_end]);
                        }
                    }
                }
            }
            _ => {}
        }

        pos += attr_len as usize;
    }

    let mut entries = Vec::new();

    if let Some((iro_start, iro_end)) = index_root_range {
        if iro_end.saturating_sub(iro_start) >= 0x20 {
            let header = iro_start + 0x10;
            if header + 0x0C <= iro_end {
                let entries_offset = u32::from_le_bytes([
                    dir_data[header],
                    dir_data[header + 1],
                    dir_data[header + 2],
                    dir_data[header + 3],
                ]) as usize;
                let total_size = u32::from_le_bytes([
                    dir_data[header + 4],
                    dir_data[header + 5],
                    dir_data[header + 6],
                    dir_data[header + 7],
                ]) as usize;
                let entries_start = header + entries_offset;
                let entries_end = entries_start.saturating_add(total_size);
                if entries_start < iro_end {
                    let capped_end = entries_end.min(iro_end).max(entries_start);
                    parse_index_entries(
                        &dir_data[entries_start..capped_end],
                        max_entries,
                        &mut entries,
                    );
                }
            }
        }
    }

    if entries.len() < max_entries as usize && !index_allocation_runs.is_empty() {
        for (lcn, cluster_count) in index_allocation_runs {
            if entries.len() >= max_entries as usize {
                break;
            }
            let run_offset =
                volume_base_offset + lcn.saturating_mul(boot.cluster_size_bytes as u64);
            let run_size = cluster_count.saturating_mul(boot.cluster_size_bytes as u64);
            if run_size == 0 || run_offset >= container.size() {
                continue;
            }
            let safe_size = run_size.min(container.size().saturating_sub(run_offset));
            let ia_data = match container.read_at(run_offset, safe_size) {
                Ok(d) => d,
                Err(_) => continue,
            };
            let mut chunk_pos = 0usize;
            while chunk_pos + 0x20 <= ia_data.len() && entries.len() < max_entries as usize {
                if &ia_data[chunk_pos..chunk_pos + 4] != b"INDX" {
                    chunk_pos = chunk_pos.saturating_add(boot.cluster_size_bytes as usize);
                    continue;
                }
                let index_header = chunk_pos + 0x18;
                if index_header + 0x10 > ia_data.len() {
                    break;
                }
                let entries_offset = u32::from_le_bytes([
                    ia_data[index_header],
                    ia_data[index_header + 1],
                    ia_data[index_header + 2],
                    ia_data[index_header + 3],
                ]) as usize;
                let total_size = u32::from_le_bytes([
                    ia_data[index_header + 4],
                    ia_data[index_header + 5],
                    ia_data[index_header + 6],
                    ia_data[index_header + 7],
                ]) as usize;
                let start = index_header + entries_offset;
                let end = start.saturating_add(total_size).min(ia_data.len());
                if start < end {
                    parse_index_entries(&ia_data[start..end], max_entries, &mut entries);
                }
                chunk_pos = chunk_pos.saturating_add(boot.cluster_size_bytes as usize);
            }
        }
    }

    Ok(entries)
}

fn parse_data_runs(data: &[u8]) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    let mut idx = 0usize;
    let mut current_lcn: i64 = 0;

    while idx < data.len() {
        let header = data[idx];
        idx += 1;
        if header == 0 {
            break;
        }

        let len_size = (header & 0x0F) as usize;
        let off_size = (header >> 4) as usize;
        if len_size == 0 || len_size > 8 || off_size > 8 || idx + len_size + off_size > data.len() {
            break;
        }

        let mut run_len_buf = [0u8; 8];
        run_len_buf[..len_size].copy_from_slice(&data[idx..idx + len_size]);
        idx += len_size;
        let run_len = u64::from_le_bytes(run_len_buf);
        if run_len == 0 {
            break;
        }

        let lcn = if off_size == 0 {
            None
        } else {
            let mut run_off_buf = [0u8; 8];
            run_off_buf[..off_size].copy_from_slice(&data[idx..idx + off_size]);
            let sign_extend = (run_off_buf[off_size - 1] & 0x80) != 0;
            if sign_extend {
                for b in &mut run_off_buf[off_size..] {
                    *b = 0xFF;
                }
            }
            idx += off_size;
            let relative = i64::from_le_bytes(run_off_buf);
            current_lcn = current_lcn.saturating_add(relative);
            Some(current_lcn)
        };

        if let Some(lcn) = lcn {
            if lcn >= 0 {
                out.push((lcn as u64, run_len));
            }
        }
    }

    out
}

fn parse_index_entries(data: &[u8], max_entries: u32, entries: &mut Vec<NtfsDirectoryEntry>) {
    let mut pos = 0;
    let mut count = 0;

    while pos + 0x52 <= data.len() && count < max_entries {
        let entry_len = u16::from_le_bytes([data[pos + 8], data[pos + 9]]);
        let stream_flags = u16::from_le_bytes([data[pos + 12], data[pos + 13]]);

        if entry_len == 0 || entry_len < 0x52 {
            break;
        }
        if pos + entry_len as usize > data.len() {
            break;
        }

        if (stream_flags & 0x2) != 0 {
            pos += entry_len as usize;
            continue;
        }

        let name_len = (data[pos + 0x50] as usize).saturating_mul(2);
        if name_len > 0 && pos + 0x52 + name_len <= data.len() {
            let name_bytes = &data[pos + 0x52..pos + 0x52 + name_len];
            let name = u16_slice_to_string(name_bytes);

            if !name.is_empty() && name != "." && name != ".." {
                let mft_ref = u64::from_le_bytes([
                    data[pos],
                    data[pos + 0x01],
                    data[pos + 0x02],
                    data[pos + 0x03],
                    data[pos + 0x04],
                    data[pos + 0x05],
                    data[pos + 0x06],
                    data[pos + 0x07],
                ]);
                let record_number = (mft_ref & 0xFFFFFFFFFFFF) as u32;
                let seq_number = ((mft_ref >> 48) & 0xFFFF) as u16;

                let is_directory = (data[pos + 0x50] & 0x01) != 0;
                let size = u64::from_le_bytes([
                    data[pos + 0x38],
                    data[pos + 0x39],
                    data[pos + 0x3A],
                    data[pos + 0x3B],
                    data[pos + 0x3C],
                    data[pos + 0x3D],
                    data[pos + 0x3E],
                    data[pos + 0x3F],
                ]);
                let created = Some(i64::from_le_bytes([
                    data[pos + 0x18],
                    data[pos + 0x19],
                    data[pos + 0x1A],
                    data[pos + 0x1B],
                    data[pos + 0x1C],
                    data[pos + 0x1D],
                    data[pos + 0x1E],
                    data[pos + 0x1F],
                ]));
                let modified = Some(i64::from_le_bytes([
                    data[pos + 0x20],
                    data[pos + 0x21],
                    data[pos + 0x22],
                    data[pos + 0x23],
                    data[pos + 0x24],
                    data[pos + 0x25],
                    data[pos + 0x26],
                    data[pos + 0x27],
                ]));
                let accessed = Some(i64::from_le_bytes([
                    data[pos + 0x30],
                    data[pos + 0x31],
                    data[pos + 0x32],
                    data[pos + 0x33],
                    data[pos + 0x34],
                    data[pos + 0x35],
                    data[pos + 0x36],
                    data[pos + 0x37],
                ]));

                entries.push(NtfsDirectoryEntry {
                    record_number,
                    sequence_number: seq_number,
                    name,
                    is_directory,
                    size,
                    created,
                    modified,
                    accessed,
                });
                if let Some(last) = entries.last() {
                    tracing::debug!(
                        "[MFT][I30] {} rec={} created={:?} modified={:?} accessed={:?}",
                        last.name,
                        last.record_number,
                        last.created,
                        last.modified,
                        last.accessed
                    );
                }

                count += 1;
            }
        }

        pos += entry_len as usize;
    }
}

pub fn extract_timeline(entries: &[NtfsFileEntry]) -> Vec<TimelineEntry> {
    let mut timeline = Vec::new();

    for entry in entries {
        let ts = match entry.timestamp() {
            Some(t) => t,
            None => continue,
        };

        let action = if entry.is_directory {
            "DIR".to_string()
        } else {
            "FILE".to_string()
        };

        let path = entry
            .name
            .clone()
            .unwrap_or_else(|| format!("{}", entry.record_number));

        timeline.push(TimelineEntry {
            timestamp: ts,
            action,
            path,
            size: if entry.is_directory {
                None
            } else {
                Some(entry.size)
            },
            record_number: entry.record_number,
        });
    }

    timeline.sort_by_key(|e| e.timestamp);
    timeline
}

#[derive(Debug, Clone)]
pub struct NtfsTreeEntry {
    pub path: String,
    pub name: String,
    pub record_number: u32,
    pub is_directory: bool,
    pub size: u64,
    pub created: Option<i64>,
    pub modified: Option<i64>,
    pub accessed: Option<i64>,
}

pub fn walk_directory_tree<C: EvidenceContainerRO>(
    container: &C,
    volume_base_offset: u64,
    start_record: u32,
    max_depth: u32,
    max_entries: u32,
) -> Result<Vec<NtfsTreeEntry>, ForensicError> {
    let sector_size = container.sector_size();
    let max_len = container.size().saturating_sub(volume_base_offset);
    let read_len = sector_size.min(max_len);

    if read_len == 0 {
        return Err(ForensicError::InvalidImageFormat);
    }

    let vbr = container.read_at(volume_base_offset, read_len)?;
    let boot = parse_boot_sector_internal(&vbr)?;

    let record_size = if boot.clusters_per_mft_record > 0 {
        (boot.clusters_per_mft_record as u32) * boot.cluster_size_bytes
    } else {
        1u32 << (-boot.clusters_per_mft_record as i32)
    };

    let mft0_rel = (boot.mft_lcn as u64) * (boot.cluster_size_bytes as u64);
    let mft_offset = volume_base_offset + mft0_rel;

    let mut results = Vec::new();
    let mut visited_records = std::collections::HashSet::new();

    #[allow(clippy::too_many_arguments)]
    fn walk_recursive<C: EvidenceContainerRO>(
        container: &C,
        volume_base_offset: u64,
        mft_offset: u64,
        record_size: u32,
        _cluster_size: u32,
        visited: &mut std::collections::HashSet<u32>,
        current_path: &str,
        record_num: u32,
        depth: u32,
        max_depth: u32,
        max_entries: u32,
        results: &mut Vec<NtfsTreeEntry>,
    ) -> Result<(), ForensicError> {
        if depth > max_depth || results.len() as u32 >= max_entries {
            return Ok(());
        }

        if visited.contains(&record_num) {
            return Ok(());
        }
        visited.insert(record_num);

        let offset = mft_offset + (record_num as u64) * (record_size as u64);
        if offset + (record_size as u64) > container.size() {
            return Ok(());
        }

        let mut data = container.read_at(offset, record_size as u64)?;
        if data.len() < 4 || data[0..4] != b"FILE"[..] {
            return Ok(());
        }

        if apply_usa_fixup(&mut data, 512).is_err() {
            return Ok(());
        }

        let flags = u16::from_le_bytes([data[0x16], data[0x17]]);

        let first_attr = u16::from_le_bytes([data[0x14], data[0x15]]) as usize;

        let mut name: Option<String> = None;
        let is_dir = (flags & 0x01) != 0;
        let mut size: u64 = 0;
        let mut created: Option<i64> = None;
        let mut modified: Option<i64> = None;
        let mut accessed: Option<i64> = None;

        let mut pos = first_attr;
        while pos + 8 <= data.len() {
            let attr_type =
                u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
            let attr_len =
                u32::from_le_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);

            if attr_len == 0 {
                break;
            }
            if pos + (attr_len as usize) > data.len() {
                break;
            }

            match attr_type {
                ATTR_STANDARD_INFORMATION => {
                    if attr_len >= 48 {
                        created = Some(i64::from_le_bytes([
                            data[pos + 8],
                            data[pos + 9],
                            data[pos + 10],
                            data[pos + 11],
                            data[pos + 12],
                            data[pos + 13],
                            data[pos + 14],
                            data[pos + 15],
                        ]));
                        modified = Some(i64::from_le_bytes([
                            data[pos + 16],
                            data[pos + 17],
                            data[pos + 18],
                            data[pos + 19],
                            data[pos + 20],
                            data[pos + 21],
                            data[pos + 22],
                            data[pos + 23],
                        ]));
                        accessed = Some(i64::from_le_bytes([
                            data[pos + 32],
                            data[pos + 33],
                            data[pos + 34],
                            data[pos + 35],
                            data[pos + 36],
                            data[pos + 37],
                            data[pos + 38],
                            data[pos + 39],
                        ]));
                    }
                }
                ATTR_FILE_NAME => {
                    if attr_len >= 66 {
                        let name_len = data[pos + 64] as usize;
                        if name_len > 0
                            && name_len < 256
                            && (attr_len as usize) >= 66 + (name_len * 2)
                        {
                            let start = pos + 66;
                            let end = start + (name_len * 2);
                            if end > data.len() {
                                break;
                            }
                            let name_bytes = &data[start..end];
                            name = Some(u16_slice_to_string(name_bytes));
                        }
                    }
                }
                ATTR_DATA => {
                    if !is_dir && attr_len >= 16 {
                        size = u64::from_le_bytes([
                            data[pos + 16],
                            data[pos + 17],
                            data[pos + 18],
                            data[pos + 19],
                            data[pos + 20],
                            data[pos + 21],
                            data[pos + 22],
                            data[pos + 23],
                        ]);
                    }
                }
                _ => {}
            }
            pos += attr_len as usize;
        }

        let entry_name = name
            .clone()
            .unwrap_or_else(|| format!("RECORD_{}", record_num));
        let full_path = if current_path.is_empty() {
            entry_name.clone()
        } else {
            format!("{}\\{}", current_path, entry_name)
        };

        results.push(NtfsTreeEntry {
            path: full_path.clone(),
            name: entry_name,
            record_number: record_num,
            is_directory: is_dir,
            size,
            created,
            modified,
            accessed,
        });
        tracing::debug!(
            "[MFT][TREE] path={} rec={} created={:?} modified={:?} accessed={:?}",
            full_path,
            record_num,
            created,
            modified,
            accessed
        );

        if is_dir && depth < max_depth && full_path.len() < 4096 {
            let vol_offset = volume_base_offset;
            if let Ok(sub_entries) = enumerate_directory(container, vol_offset, record_num, 1000) {
                for sub in sub_entries {
                    walk_recursive(
                        container,
                        vol_offset,
                        mft_offset,
                        record_size,
                        _cluster_size,
                        visited,
                        &full_path,
                        sub.record_number,
                        depth + 1,
                        max_depth,
                        max_entries,
                        results,
                    )?;
                }
            }
        }

        Ok(())
    }

    walk_recursive(
        container,
        volume_base_offset,
        mft_offset,
        record_size,
        boot.cluster_size_bytes,
        &mut visited_records,
        "",
        start_record,
        0,
        max_depth,
        max_entries,
        &mut results,
    )?;

    Ok(results)
}
