use super::scalpel::{read_prefix, DEFAULT_BINARY_MAX_BYTES};
use crate::errors::ForensicError;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct ExifData {
    pub camera_make: Option<String>,
    pub camera_model: Option<String>,
    pub date_taken: Option<i64>,
    pub date_digitized: Option<i64>,
    pub gps_latitude: Option<f64>,
    pub gps_longitude: Option<f64>,
    pub gps_altitude: Option<f64>,
    pub image_width: Option<u32>,
    pub image_height: Option<u32>,
    pub orientation: Option<u16>,
    pub iso: Option<u32>,
    pub exposure_time: Option<String>,
    pub f_number: Option<String>,
    pub focal_length: Option<String>,
    pub software: Option<String>,
    pub artist: Option<String>,
    pub copyright: Option<String>,
    pub description: Option<String>,
    pub thumbnail: Option<Vec<u8>>,
}

pub fn extract_exif(path: &Path) -> Result<ExifData, ForensicError> {
    let data = read_prefix(path, DEFAULT_BINARY_MAX_BYTES * 2)?;

    let mut exif = ExifData {
        camera_make: None,
        camera_model: None,
        date_taken: None,
        date_digitized: None,
        gps_latitude: None,
        gps_longitude: None,
        gps_altitude: None,
        image_width: None,
        image_height: None,
        orientation: None,
        iso: None,
        exposure_time: None,
        f_number: None,
        focal_length: None,
        software: None,
        artist: None,
        copyright: None,
        description: None,
        thumbnail: None,
    };

    if data.len() < 2 {
        return Ok(exif);
    }

    let format = detect_image_format(&data);

    match format {
        ImageFormat::JPEG => parse_jpeg_exif(&data, &mut exif),
        ImageFormat::PNG => parse_png_exif(&data, &mut exif),
        ImageFormat::TIFF => parse_tiff_exif(&data, &mut exif),
        _ => {}
    }

    Ok(exif)
}

#[derive(Debug, Clone, PartialEq)]
pub enum ImageFormat {
    JPEG,
    PNG,
    TIFF,
    GIF,
    BMP,
    WEBP,
    HEIC,
    RAW,
    Unknown,
}

fn detect_image_format(data: &[u8]) -> ImageFormat {
    if data.len() < 4 {
        return ImageFormat::Unknown;
    }

    if &data[0..2] == b"\xFF\xD8" {
        return ImageFormat::JPEG;
    }
    if &data[0..8] == b"\x89PNG\r\n\x1A\n" {
        return ImageFormat::PNG;
    }
    if &data[0..4] == b"II\x2A\x00" || &data[0..4] == b"MM\x00\x2A" {
        return ImageFormat::TIFF;
    }
    if &data[0..4] == b"GIF87a" || &data[0..4] == b"GIF89a" {
        return ImageFormat::GIF;
    }
    if &data[0..2] == b"BM" {
        return ImageFormat::BMP;
    }
    if &data[0..4] == b"RIFF" && data.len() > 12 && &data[8..12] == b"WEBP" {
        return ImageFormat::WEBP;
    }
    if &data[0..4] == b"ftyp" && data.len() > 12 && &data[4..8] == b"heic" {
        return ImageFormat::HEIC;
    }
    if &data[0..4] == b"CR\x00\xFF" || &data[0..4] == b"CR\x00\xFE" {
        return ImageFormat::RAW;
    }

    ImageFormat::Unknown
}

fn parse_jpeg_exif(data: &[u8], exif: &mut ExifData) {
    let mut offset = 2;

    while offset + 4 < data.len() {
        if data[offset] != 0xFF {
            offset += 1;
            continue;
        }

        let marker = data[offset + 1];

        if marker == 0xD9 || marker == 0xD8 {
            break;
        }

        if marker == 0xE1 {
            let length = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            let exif_offset = offset + 4;

            if data.len() > exif_offset + 6 && data[exif_offset..exif_offset + 4] == b"Exif"[..] {
                parse_exif_ifd(&data[exif_offset + 6..], exif);
            }
            offset += length + 2;
        } else if (0xC0..=0xCF).contains(&marker)
            && marker != 0xC4
            && marker != 0xC8
            && marker != 0xCC
        {
            let length = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            offset += length + 2;
        } else {
            offset += 2;
        }
    }
}

fn parse_png_exif(data: &[u8], exif: &mut ExifData) {
    let mut offset = 8;

    while offset + 12 < data.len() {
        let chunk_size = u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize;
        let chunk_type = &data[offset + 4..offset + 8];

        if chunk_type == b"eXIf" {
            parse_exif_ifd(&data[offset + 8..offset + 8 + chunk_size.min(65536)], exif);
            break;
        }

        if chunk_type == b"IEND" {
            break;
        }

        offset += 12 + chunk_size;
    }
}

fn parse_tiff_exif(data: &[u8], exif: &mut ExifData) {
    let _byte_order = if &data[0..2] == b"II" {
        "little"
    } else {
        "big"
    };
    parse_exif_ifd(data, exif);
}

fn parse_exif_ifd(data: &[u8], exif: &mut ExifData) {
    if data.len() < 2 {
        return;
    }

    let is_little_endian = &data[0..2] == b"II";

    let ifd_offset = if is_little_endian {
        u32::from_le_bytes([data[4], data[5], data[6], data[7]])
    } else {
        u32::from_be_bytes([data[4], data[5], data[6], data[7]])
    } as usize;

    if ifd_offset + 2 > data.len() {
        return;
    }

    let num_entries = if is_little_endian {
        u16::from_le_bytes([data[ifd_offset], data[ifd_offset + 1]])
    } else {
        u16::from_be_bytes([data[ifd_offset], data[ifd_offset + 1]])
    };

    let mut offset = ifd_offset + 2;

    for _ in 0..num_entries {
        if offset + 12 > data.len() {
            break;
        }

        let tag = if is_little_endian {
            u16::from_le_bytes([data[offset], data[offset + 1]])
        } else {
            u16::from_be_bytes([data[offset], data[offset + 1]])
        };

        let _value_type = if is_little_endian {
            u16::from_le_bytes([data[offset + 2], data[offset + 3]])
        } else {
            u16::from_be_bytes([data[offset + 2], data[offset + 3]])
        };

        let count = if is_little_endian {
            u32::from_le_bytes([
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ])
        } else {
            u32::from_be_bytes([
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ])
        };

        let value_offset = offset + 8;

        match tag {
            0x010F => exif.camera_make = read_string(data, value_offset, count, is_little_endian),
            0x0110 => exif.camera_model = read_string(data, value_offset, count, is_little_endian),
            0x0132 => exif.date_digitized = read_datetime(data, value_offset, is_little_endian),
            0x013B => exif.artist = read_string(data, value_offset, count, is_little_endian),
            0x8298 => exif.copyright = read_string(data, value_offset, count, is_little_endian),
            0x8769 => {
                let exif_ifd_offset = if is_little_endian {
                    u32::from_le_bytes([
                        data[value_offset],
                        data[value_offset + 1],
                        data[value_offset + 2],
                        data[value_offset + 3],
                    ])
                } else {
                    u32::from_be_bytes([
                        data[value_offset],
                        data[value_offset + 1],
                        data[value_offset + 2],
                        data[value_offset + 3],
                    ])
                } as usize;
                parse_exif_subifd(data, exif_ifd_offset, exif, is_little_endian);
            }
            _ => {}
        }

        offset += 12;
    }
}

fn parse_exif_subifd(data: &[u8], offset: usize, exif: &mut ExifData, is_little_endian: bool) {
    if offset + 2 > data.len() {
        return;
    }

    let num_entries = if is_little_endian {
        u16::from_le_bytes([data[offset], data[offset + 1]])
    } else {
        u16::from_be_bytes([data[offset], data[offset + 1]])
    };

    let mut pos = offset + 2;

    for _ in 0..num_entries {
        if pos + 12 > data.len() {
            break;
        }

        let tag = if is_little_endian {
            u16::from_le_bytes([data[pos], data[pos + 1]])
        } else {
            u16::from_be_bytes([data[pos], data[pos + 1]])
        };

        let _count = if is_little_endian {
            u32::from_le_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]])
        } else {
            u32::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]])
        };

        let value_offset = pos + 8;

        match tag {
            0x9003 => exif.date_taken = read_datetime(data, value_offset, is_little_endian),
            0xA002 => exif.image_width = read_short(data, value_offset, is_little_endian),
            0xA003 => exif.image_height = read_short(data, value_offset, is_little_endian),
            0xA012 => exif.focal_length = read_rational(data, value_offset, is_little_endian),
            0xA20E => exif.focal_length = read_rational(data, value_offset, is_little_endian),
            _ => {}
        }

        pos += 12;
    }
}

fn read_string(data: &[u8], offset: usize, count: u32, _is_little_endian: bool) -> Option<String> {
    if offset + 4 > data.len() {
        return None;
    }

    let actual_offset = u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;

    if actual_offset + (count as usize) > data.len() {
        return None;
    }

    let slice = &data[actual_offset..actual_offset + (count as usize).min(256)];
    let s = String::from_utf8_lossy(slice)
        .trim_end_matches('\0')
        .to_string();

    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn read_datetime(data: &[u8], offset: usize, is_little_endian: bool) -> Option<i64> {
    let str_offset = if is_little_endian {
        u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize
    } else {
        u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize
    };

    if str_offset + 20 > data.len() {
        return None;
    }

    let datetime_str = String::from_utf8_lossy(&data[str_offset..str_offset + 19]).to_string();

    parse_exif_datetime(&datetime_str)
}

fn parse_exif_datetime(datetime: &str) -> Option<i64> {
    if datetime.len() < 19 {
        return None;
    }

    let parts: Vec<&str> = datetime.split([' ', ':', '-']).collect();

    if parts.len() < 6 {
        return None;
    }

    let year: i64 = parts[0].parse().ok()?;
    let month: i64 = parts[1].parse().ok()?;
    let day: i64 = parts[2].parse().ok()?;
    let hour: i64 = parts[3].parse().ok()?;
    let minute: i64 = parts[4].parse().ok()?;
    let second: i64 = parts[5].parse().ok()?;

    let days_since_epoch = days_since_ymd(year, month, day);
    let seconds = ((days_since_epoch * 24 + hour) * 60 + minute) * 60 + second;

    Some(seconds)
}

fn days_since_ymd(year: i64, month: i64, day: i64) -> i64 {
    let mut days =
        (year - 1970) * 365 + (year - 1969) / 4 - (year - 1901) / 100 + (year - 1601) / 400;

    let month_days = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for m in 1..month {
        days += month_days[(m - 1) as usize] as i64;
    }

    if month > 2 && (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)) {
        days += 1;
    }

    days + day - 1
}

fn read_short(data: &[u8], offset: usize, is_little_endian: bool) -> Option<u32> {
    if offset + 2 > data.len() {
        return None;
    }

    Some(if is_little_endian {
        u16::from_le_bytes([data[offset], data[offset + 1]])
    } else {
        u16::from_be_bytes([data[offset], data[offset + 1]])
    } as u32)
}

fn read_rational(data: &[u8], offset: usize, is_little_endian: bool) -> Option<String> {
    if offset + 8 > data.len() {
        return None;
    }

    let num = if is_little_endian {
        u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ])
    } else {
        u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ])
    };

    let den = if is_little_endian {
        u32::from_le_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ])
    } else {
        u32::from_be_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ])
    };

    if den == 0 {
        return None;
    }

    Some(format!("{}/{}", num, den))
}
