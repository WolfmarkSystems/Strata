//! EXIF deep parser (EXIF-1).
//!
//! Parses EXIF metadata via the `kamadak-exif` crate. Supports JPEG,
//! TIFF, PNG (iTXt-embedded EXIF), and HEIC.
//!
//! MITRE: T1592.001 (victim identity info), T1430 (location).
//!
//! Zero `unwrap`, zero `unsafe`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use std::fs;
use std::io::BufReader;
use std::path::Path;

#[derive(Debug, Clone, PartialEq)]
pub struct ExifRecord {
    pub path: String,
    pub gps_latitude: Option<f64>,
    pub gps_longitude: Option<f64>,
    pub gps_altitude: Option<f64>,
    pub device_make: Option<String>,
    pub device_model: Option<String>,
    pub date_taken: Option<DateTime<Utc>>,
    pub date_modified: Option<DateTime<Utc>>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub software: Option<String>,
    pub has_gps: bool,
    pub timestamp_mismatch: bool,
}

pub fn is_image_path(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    name.ends_with(".jpg")
        || name.ends_with(".jpeg")
        || name.ends_with(".tif")
        || name.ends_with(".tiff")
        || name.ends_with(".heic")
        || name.ends_with(".heif")
        || name.ends_with(".png")
}

pub fn parse(path: &Path) -> Option<ExifRecord> {
    if !is_image_path(path) {
        return None;
    }
    let f = fs::File::open(path).ok()?;
    let mut reader = BufReader::new(&f);
    let exif = exif::Reader::new().read_from_container(&mut reader).ok()?;
    let meta = fs::metadata(path).ok();
    let date_modified = meta
        .as_ref()
        .and_then(|m| m.modified().ok())
        .map(DateTime::<Utc>::from);
    let date_taken = read_string(&exif, exif::Tag::DateTimeOriginal)
        .or_else(|| read_string(&exif, exif::Tag::DateTime))
        .and_then(parse_exif_datetime);
    let device_make = read_string(&exif, exif::Tag::Make);
    let device_model = read_string(&exif, exif::Tag::Model);
    let software = read_string(&exif, exif::Tag::Software);
    let width = read_u32(&exif, exif::Tag::PixelXDimension)
        .or_else(|| read_u32(&exif, exif::Tag::ImageWidth));
    let height = read_u32(&exif, exif::Tag::PixelYDimension)
        .or_else(|| read_u32(&exif, exif::Tag::ImageLength));
    let gps_latitude = read_gps_coord(
        &exif,
        exif::Tag::GPSLatitude,
        exif::Tag::GPSLatitudeRef,
        "S",
    );
    let gps_longitude = read_gps_coord(
        &exif,
        exif::Tag::GPSLongitude,
        exif::Tag::GPSLongitudeRef,
        "W",
    );
    let gps_altitude = read_f64(&exif, exif::Tag::GPSAltitude);
    let has_gps = gps_latitude.is_some() || gps_longitude.is_some();
    let timestamp_mismatch = match (date_taken, date_modified) {
        (Some(t1), Some(t2)) => (t1.timestamp() - t2.timestamp()).abs() > 60,
        _ => false,
    };
    Some(ExifRecord {
        path: path.to_string_lossy().to_string(),
        gps_latitude,
        gps_longitude,
        gps_altitude,
        device_make,
        device_model,
        date_taken,
        date_modified,
        width,
        height,
        software,
        has_gps,
        timestamp_mismatch,
    })
}

fn read_string(exif: &exif::Exif, tag: exif::Tag) -> Option<String> {
    let field = exif.get_field(tag, exif::In::PRIMARY)?;
    let s = field
        .display_value()
        .with_unit(exif)
        .to_string()
        .trim_matches('"')
        .to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn read_u32(exif: &exif::Exif, tag: exif::Tag) -> Option<u32> {
    let field = exif.get_field(tag, exif::In::PRIMARY)?;
    field.value.get_uint(0)
}

fn read_f64(exif: &exif::Exif, tag: exif::Tag) -> Option<f64> {
    let field = exif.get_field(tag, exif::In::PRIMARY)?;
    match &field.value {
        exif::Value::Rational(r) if !r.is_empty() => {
            let first = &r[0];
            if first.denom == 0 {
                None
            } else {
                Some(first.num as f64 / first.denom as f64)
            }
        }
        _ => None,
    }
}

fn read_gps_coord(
    exif: &exif::Exif,
    coord: exif::Tag,
    reference: exif::Tag,
    negative_ref: &str,
) -> Option<f64> {
    let field = exif.get_field(coord, exif::In::PRIMARY)?;
    let rationals = match &field.value {
        exif::Value::Rational(r) if r.len() >= 3 => r,
        _ => return None,
    };
    let to_f64 = |r: &exif::Rational| {
        if r.denom == 0 {
            0.0
        } else {
            r.num as f64 / r.denom as f64
        }
    };
    let deg = to_f64(&rationals[0]);
    let min = to_f64(&rationals[1]);
    let sec = to_f64(&rationals[2]);
    let mut decimal = deg + min / 60.0 + sec / 3600.0;
    let ref_str = read_string(exif, reference).unwrap_or_default();
    if ref_str.eq_ignore_ascii_case(negative_ref) {
        decimal = -decimal;
    }
    Some(decimal)
}

fn parse_exif_datetime(s: String) -> Option<DateTime<Utc>> {
    // EXIF DateTimeOriginal format: "YYYY:MM:DD HH:MM:SS".
    let cleaned: String = s.chars().filter(|c| *c != '\0').collect();
    for fmt in ["%Y:%m:%d %H:%M:%S", "%Y-%m-%d %H:%M:%S"] {
        if let Ok(ndt) = NaiveDateTime::parse_from_str(cleaned.trim(), fmt) {
            return Some(Utc.from_utc_datetime(&ndt));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_image_path_accepts_known_extensions() {
        for ext in ["JPG", "jpeg", "TIF", "tiff", "heic", "HEIF", "png"] {
            assert!(is_image_path(Path::new(&format!("/x/image.{}", ext))));
        }
        assert!(!is_image_path(Path::new("/x/file.txt")));
    }

    #[test]
    fn parse_returns_none_for_non_image() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("notes.txt");
        std::fs::write(&path, b"hello").expect("write");
        assert!(parse(&path).is_none());
    }

    #[test]
    fn parse_exif_datetime_round_trip() {
        let dt = parse_exif_datetime("2024:06:01 12:00:00".to_string()).expect("parses");
        assert_eq!(dt.timestamp(), 1_717_243_200);
    }

    #[test]
    fn parse_ignores_malformed_exif_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bad.jpg");
        std::fs::write(&path, b"not a jpeg").expect("write");
        // parse() returns None on malformed input, never panics.
        let _ = parse(&path);
    }
}
