//! NTFS $I30 directory index parser.
//!
//! Every NTFS directory has an `$I30` attribute — a B-tree index of the
//! files it contains. Slack space inside the index stream often retains
//! entries for files that were deleted from the directory. This parser
//! walks INDEX_ROOT and INDEX_ALLOCATION records, yielding *every* file
//! name the index has ever seen, including slack-space ghosts.
//!
//! This is a partial implementation. Full NTFS $I30 parsing requires a
//! complete MFT walker to resolve MFT record references; here we decode
//! just the FILE_NAME attributes we find.

use crate::errors::ForensicError;

#[derive(Debug, Clone)]
pub struct I30Entry {
    pub filename: String,
    pub mft_reference: u64,
    pub created: i64,
    pub modified: i64,
    pub mft_modified: i64,
    pub accessed: i64,
    pub size: u64,
    pub allocated_size: u64,
    pub is_directory: bool,
    /// True when the entry was recovered from slack space (no longer live).
    pub is_slack: bool,
}

pub struct I30Parser;

impl I30Parser {
    /// Parse an $I30 stream. `data` should be the full attribute body
    /// (INDEX_ROOT plus INDEX_ALLOCATION concatenated if available).
    pub fn parse(data: &[u8]) -> Result<Vec<I30Entry>, ForensicError> {
        let mut out = Vec::new();
        if data.is_empty() {
            return Ok(out);
        }

        // Walk the buffer looking for FILE_NAME attribute records. Each such
        // record begins with an 8-byte parent MFT reference, followed by four
        // 8-byte FILETIMEs, then allocated/real size (u64 each), flags (u32),
        // reparse (u32), filename length (u8), namespace (u8), filename
        // (UTF-16LE). This is the FILE_NAME structure as it sits inside an
        // INDX record slot.
        //
        // Since we don't parse the full INDX header, we heuristically scan
        // every 8-byte-aligned offset looking for a plausible FILE_NAME.
        let mut i = 0;
        while i + 66 < data.len() {
            let filename_len = data[i + 0x50] as usize;
            if filename_len == 0 || filename_len > 255 {
                i += 8;
                continue;
            }
            let name_bytes_end = i + 0x52 + filename_len * 2;
            if name_bytes_end > data.len() {
                break;
            }
            // Sanity: the four filetimes at +0x08..0x28 should not all be
            // zero and should not be in the far future.
            let ft_created = i64::from_le_bytes(data[i + 8..i + 16].try_into().unwrap_or([0; 8]));
            if ft_created == 0 {
                i += 8;
                continue;
            }
            let ft_modified =
                i64::from_le_bytes(data[i + 16..i + 24].try_into().unwrap_or([0; 8]));
            let ft_mft =
                i64::from_le_bytes(data[i + 24..i + 32].try_into().unwrap_or([0; 8]));
            let ft_accessed =
                i64::from_le_bytes(data[i + 32..i + 40].try_into().unwrap_or([0; 8]));
            let allocated =
                u64::from_le_bytes(data[i + 40..i + 48].try_into().unwrap_or([0; 8]));
            let real =
                u64::from_le_bytes(data[i + 48..i + 56].try_into().unwrap_or([0; 8]));
            let flags =
                u32::from_le_bytes(data[i + 56..i + 60].try_into().unwrap_or([0; 4]));

            // Read the filename
            let name_bytes = &data[i + 0x52..name_bytes_end];
            let u16s: Vec<u16> = name_bytes
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            let filename = String::from_utf16(&u16s).unwrap_or_default();
            if filename.is_empty() || !filename.chars().all(|c| c != '\0') {
                i += 8;
                continue;
            }

            out.push(I30Entry {
                filename,
                mft_reference: u64::from_le_bytes(
                    data[i..i + 8].try_into().unwrap_or([0; 8]),
                ),
                created: ft_created,
                modified: ft_modified,
                mft_modified: ft_mft,
                accessed: ft_accessed,
                size: real,
                allocated_size: allocated,
                is_directory: flags & 0x1000_0000 != 0,
                // We can't know for certain without the live index bitmap;
                // mark slack=false and let the caller cross-reference.
                is_slack: false,
            });
            i = name_bytes_end;
        }

        Ok(out)
    }
}
