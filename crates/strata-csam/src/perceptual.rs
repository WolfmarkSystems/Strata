//! Perceptual hashing — dHash (difference hash).
//!
//! dHash is the standard open algorithm used by forensic tools.
//! It catches edits that exact cryptographic hashes miss: crops,
//! resizes, JPEG recompression, minor pixel edits.
//!
//! ## Algorithm (must remain stable for reproducibility)
//!
//! 1. Decode image bytes into a `DynamicImage`.
//! 2. Resize to **9 × 8** pixels using a Triangle filter.
//! 3. Convert to 8-bit grayscale (`Luma<u8>`).
//! 4. For each of the 8 rows, compare 8 adjacent pixel pairs
//!    (columns 0-1, 1-2, ..., 7-8). If `pixel[col] > pixel[col+1]`
//!    set the bit, else clear it.
//! 5. The 64 bits form a `u64`, packed in scan order
//!    (row 0 col 0 → bit 0, row 7 col 7 → bit 63).
//!
//! Forensic reproducibility means this must NEVER change without
//! a major version bump and a re-hash of stored databases.

use anyhow::{anyhow, bail, Context, Result};
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Compute a 64-bit dHash for an image.
///
/// Returns `None` if the bytes cannot be decoded as a supported
/// image format. This is a recoverable miss — the scanner should
/// log it and continue.
pub fn compute_dhash(image_bytes: &[u8]) -> Option<u64> {
    let img = image::load_from_memory(image_bytes).ok()?;
    let resized = img.resize_exact(9, 8, image::imageops::FilterType::Triangle);
    let gray = resized.to_luma8();

    debug_assert_eq!(gray.width(), 9);
    debug_assert_eq!(gray.height(), 8);

    let mut hash: u64 = 0;
    let mut bit: u32 = 0;
    for row in 0..8u32 {
        for col in 0..8u32 {
            let left = gray.get_pixel(col, row).0[0];
            let right = gray.get_pixel(col + 1, row).0[0];
            if left > right {
                hash |= 1u64 << bit;
            }
            bit += 1;
        }
    }
    Some(hash)
}

/// Hamming distance between two perceptual hashes.
///
/// `0` = identical, `< 10` = likely the same image.
#[inline]
pub fn hamming_distance(a: u64, b: u64) -> u32 {
    (a ^ b).count_ones()
}

/// Format a dHash as a 16-character lowercase hex string for storage.
pub fn dhash_to_hex(hash: u64) -> String {
    format!("{:016x}", hash)
}

/// Parse a stored hex dHash back into a `u64`.
///
/// Accepts uppercase or lowercase but requires exactly 16 characters.
pub fn hex_to_dhash(hex: &str) -> Result<u64> {
    if hex.len() != 16 {
        bail!("dHash hex must be 16 characters, got {}", hex.len());
    }
    u64::from_str_radix(hex, 16).map_err(|e| anyhow!("invalid dHash hex {:?}: {}", hex, e))
}

// ──────────────────────────────────────────────────────────────────────
// Perceptual hash database
// ──────────────────────────────────────────────────────────────────────

/// In-memory perceptual hash database.
///
/// The current implementation does a linear scan across all stored
/// hashes for each query. That's fine for the typical examiner case
/// (thousands of perceptual hashes); for very large databases a
/// VP-tree or BK-tree would be more efficient.
#[derive(Debug)]
pub struct PerceptualHashDb {
    hashes: Vec<(u64, String)>,
    threshold: u32,
}

impl Default for PerceptualHashDb {
    fn default() -> Self {
        Self {
            hashes: Vec::new(),
            threshold: 10,
        }
    }
}

impl PerceptualHashDb {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_threshold(threshold: u32) -> Self {
        Self {
            hashes: Vec::new(),
            threshold,
        }
    }

    pub fn threshold(&self) -> u32 {
        self.threshold
    }

    pub fn set_threshold(&mut self, threshold: u32) {
        self.threshold = threshold;
    }

    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }

    pub fn add_hash(&mut self, hash: u64, source: &str) {
        self.hashes.push((hash, source.to_string()));
    }

    /// Import a perceptual hash list from a text file.
    ///
    /// Format (one entry per line):
    ///
    /// ```text
    /// <16-hex-dhash>  <source-identifier>
    /// # comments and blank lines allowed
    /// ```
    ///
    /// The hash and the source identifier are separated by ASCII
    /// whitespace; everything after the first whitespace block is
    /// the identifier (so identifiers may contain spaces).
    pub fn import_from_file(path: &Path) -> Result<Self> {
        let file = File::open(path)
            .with_context(|| format!("opening perceptual hash file {}", path.display()))?;
        let reader = BufReader::new(file);

        let mut db = PerceptualHashDb::new();
        let mut seen: HashSet<u64> = HashSet::new();

        for (line_no, line) in reader.lines().enumerate() {
            let line = line.with_context(|| format!("reading line {}", line_no + 1))?;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let mut parts = trimmed.splitn(2, char::is_whitespace);
            let hex_part = parts.next().unwrap_or("");
            let source_part = parts.next().unwrap_or("").trim();

            let hash = hex_to_dhash(hex_part).with_context(|| format!("line {}", line_no + 1))?;
            let source = if source_part.is_empty() {
                hex_part.to_string()
            } else {
                source_part.to_string()
            };

            if seen.insert(hash) {
                db.add_hash(hash, &source);
            }
        }

        if db.is_empty() {
            bail!("perceptual hash file contained no entries");
        }
        Ok(db)
    }

    /// Find the closest stored hash within the configured threshold.
    ///
    /// Returns `(distance, source)` for the best match, or `None` if
    /// no stored hash is within `self.threshold` of the query.
    pub fn find_match(&self, query: u64) -> Option<(u32, &str)> {
        let mut best: Option<(u32, &str)> = None;
        for (h, src) in &self.hashes {
            let d = hamming_distance(query, *h);
            if d > self.threshold {
                continue;
            }
            match best {
                None => best = Some((d, src.as_str())),
                Some((bd, _)) if d < bd => best = Some((d, src.as_str())),
                _ => {}
            }
            // Distance 0 is exact — short-circuit.
            if d == 0 {
                break;
            }
        }
        best
    }
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageFormat, Rgb, RgbImage};
    use std::io::{Cursor, Write};
    use tempfile::NamedTempFile;

    /// Encode an `RgbImage` as in-memory PNG bytes.
    fn encode_png(img: &RgbImage) -> Vec<u8> {
        let mut buf = Vec::new();
        img.write_to(&mut Cursor::new(&mut buf), ImageFormat::Png)
            .expect("png encode");
        buf
    }

    /// Generate a `size`×`size` checkerboard with `square_size`-pixel
    /// squares. Produces a rich pattern with many high/low transitions
    /// — useful for exercising dHash bit variation.
    fn checkerboard(size: u32, square_size: u32) -> Vec<u8> {
        let mut img = RgbImage::new(size, size);
        for y in 0..size {
            for x in 0..size {
                let cx = x / square_size;
                let cy = y / square_size;
                let v: u8 = if (cx + cy).is_multiple_of(2) { 255 } else { 0 };
                img.put_pixel(x, y, Rgb([v, v, v]));
            }
        }
        encode_png(&img)
    }

    /// Same checkerboard pattern as `checkerboard` but with a
    /// `patch_size`×`patch_size` SOLID-WHITE region stamped in the
    /// top-left corner. Setting to white (rather than mid-gray)
    /// shifts the local mean meaningfully against the ~127 checker
    /// average so the post-resize cell value actually changes.
    fn checkerboard_with_patch(size: u32, square_size: u32, patch_size: u32) -> Vec<u8> {
        let mut img = RgbImage::new(size, size);
        for y in 0..size {
            for x in 0..size {
                let cx = x / square_size;
                let cy = y / square_size;
                let v: u8 = if (cx + cy).is_multiple_of(2) { 255 } else { 0 };
                img.put_pixel(x, y, Rgb([v, v, v]));
            }
        }
        for y in 0..patch_size {
            for x in 0..patch_size {
                img.put_pixel(x, y, Rgb([255, 255, 255]));
            }
        }
        encode_png(&img)
    }

    #[test]
    fn dhash_identical_images_distance_zero() {
        let bytes = checkerboard(64, 8);
        let h1 = compute_dhash(&bytes).expect("decode");
        let h2 = compute_dhash(&bytes).expect("decode");
        assert_eq!(hamming_distance(h1, h2), 0);
    }

    #[test]
    fn dhash_re_encoded_same_pixels_distance_zero() {
        // Re-encode the same RgbImage twice — PNG is lossless so the
        // pixel buffer is byte-identical. Hash must be identical too.
        let mut img = RgbImage::new(64, 64);
        for y in 0..64 {
            for x in 0..64 {
                let v = ((x * 7 + y * 13) ^ (x * 3 + y * 11)) as u8;
                img.put_pixel(x, y, Rgb([v, v, v]));
            }
        }
        let a = encode_png(&img);
        let b = encode_png(&img);
        let h1 = compute_dhash(&a).unwrap();
        let h2 = compute_dhash(&b).unwrap();
        assert_eq!(hamming_distance(h1, h2), 0);
    }

    #[test]
    fn dhash_slight_edit_under_ten() {
        // Same checkerboard, one with a 12×12 white corner patch.
        // 64×64 → 9×8 means each output cell covers ~7×8 input pixels,
        // so a 12×12 patch covers roughly one full output cell plus
        // partial neighbours — enough to flip a small handful of bits
        // but not enough to drift past the < 10 likely-match cutoff.
        let base = checkerboard(64, 8);
        let edited = checkerboard_with_patch(64, 8, 12);
        let h_base = compute_dhash(&base).unwrap();
        let h_edit = compute_dhash(&edited).unwrap();
        let d = hamming_distance(h_base, h_edit);
        assert!(
            d > 0,
            "expected nonzero distance for edited image, got {}",
            d
        );
        assert!(d < 10, "expected distance < 10, got {}", d);
    }

    #[test]
    fn dhash_different_images_distance_over_fifteen() {
        // Two checkerboards with very different square sizes produce
        // structurally different downsampled patterns.
        let a = checkerboard(64, 8);
        let b = checkerboard(64, 16);
        let h1 = compute_dhash(&a).unwrap();
        let h2 = compute_dhash(&b).unwrap();
        let d = hamming_distance(h1, h2);
        assert!(d > 15, "expected distance > 15, got {}", d);
    }

    #[test]
    fn dhash_undecodable_returns_none() {
        let garbage = b"this is definitely not an image";
        assert!(compute_dhash(garbage).is_none());
    }

    #[test]
    fn hex_round_trip() {
        let h = 0x1234_5678_9abc_def0u64;
        let s = dhash_to_hex(h);
        assert_eq!(s.len(), 16);
        assert_eq!(hex_to_dhash(&s).unwrap(), h);
    }

    #[test]
    fn hex_round_trip_zero() {
        let s = dhash_to_hex(0);
        assert_eq!(s, "0000000000000000");
        assert_eq!(hex_to_dhash(&s).unwrap(), 0);
    }

    #[test]
    fn hex_rejects_wrong_length() {
        assert!(hex_to_dhash("abc").is_err());
        assert!(hex_to_dhash("12345678901234567").is_err()); // 17
    }

    #[test]
    fn hex_rejects_non_hex() {
        assert!(hex_to_dhash("zzzzzzzzzzzzzzzz").is_err());
    }

    #[test]
    fn perceptual_db_find_exact_match() {
        let mut db = PerceptualHashDb::new();
        db.add_hash(0x1234_5678_9abc_def0, "image_a.jpg");
        db.add_hash(0xffff_ffff_ffff_ffff, "image_b.jpg");

        let m = db.find_match(0x1234_5678_9abc_def0).unwrap();
        assert_eq!(m.0, 0);
        assert_eq!(m.1, "image_a.jpg");
    }

    #[test]
    fn perceptual_db_find_close_match() {
        let mut db = PerceptualHashDb::new();
        db.add_hash(0x0000_0000_0000_0000, "ref.jpg");
        // Distance 3
        let query = 0x0000_0000_0000_0007u64;
        let m = db.find_match(query).unwrap();
        assert_eq!(m.0, 3);
        assert_eq!(m.1, "ref.jpg");
    }

    #[test]
    fn perceptual_db_no_match_above_threshold() {
        let mut db = PerceptualHashDb::with_threshold(5);
        db.add_hash(0x0000_0000_0000_0000, "ref.jpg");
        // Distance 8 > threshold 5
        let query = 0x0000_0000_0000_00ffu64;
        assert!(db.find_match(query).is_none());
    }

    #[test]
    fn perceptual_db_returns_closest() {
        // query = 0
        // "far"   = 0x0F → popcount(0^0x0F) = 4
        // "close" = 0x01 → popcount(0^0x01) = 1
        // find_match must walk past "far" and prefer "close".
        let mut db = PerceptualHashDb::with_threshold(15);
        db.add_hash(0x0000_0000_0000_000F, "far");
        db.add_hash(0x0000_0000_0000_0001, "close");
        let m = db.find_match(0).unwrap();
        assert_eq!(m.1, "close");
        assert_eq!(m.0, 1);
    }

    #[test]
    fn perceptual_db_import_from_file() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "# perceptual hash test list").unwrap();
        writeln!(f, "1234567890abcdef  source one").unwrap();
        writeln!(f, "fedcba9876543210  source two with spaces").unwrap();
        writeln!(f).unwrap();
        writeln!(f, "0000000000000000").unwrap();
        f.flush().unwrap();

        let db = PerceptualHashDb::import_from_file(f.path()).unwrap();
        assert_eq!(db.len(), 3);

        let m1 = db.find_match(0x1234567890abcdef).unwrap();
        assert_eq!(m1.0, 0);
        assert_eq!(m1.1, "source one");

        let m2 = db.find_match(0xfedcba9876543210).unwrap();
        assert_eq!(m2.1, "source two with spaces");

        // Bare hash with no identifier defaults to the hex string.
        let m3 = db.find_match(0).unwrap();
        assert_eq!(m3.1, "0000000000000000");
    }

    #[test]
    fn perceptual_db_import_rejects_bad_hex() {
        // 16 chars but not hex — exercises the hex-validation path,
        // not the wrong-length path.
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "zzzzzzzzzzzzzzzz  source").unwrap();
        f.flush().unwrap();
        let err = PerceptualHashDb::import_from_file(f.path()).unwrap_err();
        let full = format!("{:#}", err);
        assert!(full.contains("invalid"), "got: {}", full);
    }

    #[test]
    fn perceptual_db_import_rejects_empty() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "# nothing here").unwrap();
        f.flush().unwrap();
        let err = PerceptualHashDb::import_from_file(f.path()).unwrap_err();
        assert!(format!("{:#}", err).contains("no entries"));
    }
}
