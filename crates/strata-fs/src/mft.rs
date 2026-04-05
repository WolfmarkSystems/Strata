use crate::container::EvidenceContainerRO;
use crate::errors::ForensicError;

#[derive(Debug, Clone)]
pub struct MasterFileTable {
    pub entries: Vec<MftEntry>,
    pub total_entries: usize,
}

#[derive(Debug, Clone)]
pub struct MftEntry {
    pub record_number: u32,
    pub sequence_number: u16,
    pub flags: u16,
    pub allocated_size: u64,
    pub real_size: u64,
    pub timestamps: FileTimestamps,
    pub filename: Option<String>,
}

#[derive(Debug, Clone)]
pub struct FileTimestamps {
    pub created: Option<i64>,
    pub modified: Option<i64>,
    pub accessed: Option<i64>,
}

pub fn parse_mft_file<C: EvidenceContainerRO>(
    container: &C,
    mft_offset: u64,
    record_size: u32,
) -> Result<MasterFileTable, ForensicError> {
    let mut entries = Vec::new();
    let mut offset = mft_offset;
    let container_size = container.size();
    let max_records = 10000;

    for _ in 0..max_records {
        if offset + record_size as u64 > container_size {
            break;
        }

        let data = container.read_at(offset, record_size as u64)?;

        if data.len() < 48 {
            break;
        }

        if &data[0..4] == b"FILE" {
            let record_number = u32::from_le_bytes([data[44], data[45], data[46], data[47]]);
            let sequence_number = u16::from_le_bytes([data[40], data[41]]);
            let flags = u16::from_le_bytes([data[42], data[43]]);

            if flags == 0 || flags == 1 {
                let allocated_size = u64::from_le_bytes([
                    data[28], data[29], data[30], data[31], data[32], data[33], data[34], data[35],
                ]);
                let real_size = u64::from_le_bytes([
                    data[36], data[37], data[38], data[39], data[40], data[41], data[42], data[43],
                ]);

                let timestamps = parse_timestamps(&data[24..40]);

                entries.push(MftEntry {
                    record_number,
                    sequence_number,
                    flags,
                    allocated_size,
                    real_size,
                    timestamps,
                    filename: None,
                });
            }
        } else {
            break;
        }

        offset += record_size as u64;
    }

    let total = entries.len();
    Ok(MasterFileTable {
        entries,
        total_entries: total,
    })
}

fn parse_timestamps(data: &[u8]) -> FileTimestamps {
    fn parse_ft(ts: &[u8]) -> Option<i64> {
        if ts.len() < 8 {
            return None;
        }
        let v = u64::from_le_bytes([ts[0], ts[1], ts[2], ts[3], ts[4], ts[5], ts[6], ts[7]]);
        if v == 0 {
            None
        } else {
            Some((v / 10_000_000 - 11644473600) as i64)
        }
    }

    FileTimestamps {
        created: parse_ft(&data[0..8]),
        modified: parse_ft(&data[8..16]),
        accessed: parse_ft(&data[16..24]),
    }
}
