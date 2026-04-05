use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct FileSignature {
    pub extension: String,
    pub description: String,
    pub offset: u64,
    pub magic: Vec<u8>,
    pub is_aligned: bool,
}

pub fn get_known_signatures() -> HashMap<&'static str, Vec<FileSignature>> {
    let mut sigs = HashMap::new();

    sigs.insert(
        "jpg",
        vec![FileSignature {
            extension: "jpg".into(),
            description: "JPEG".into(),
            offset: 0,
            magic: vec![0xFF, 0xD8, 0xFF],
            is_aligned: false,
        }],
    );

    sigs.insert(
        "jpeg",
        vec![FileSignature {
            extension: "jpeg".into(),
            description: "JPEG".into(),
            offset: 0,
            magic: vec![0xFF, 0xD8, 0xFF],
            is_aligned: false,
        }],
    );

    sigs.insert(
        "png",
        vec![FileSignature {
            extension: "png".into(),
            description: "PNG".into(),
            offset: 0,
            magic: vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
            is_aligned: false,
        }],
    );

    sigs.insert(
        "gif",
        vec![
            FileSignature {
                extension: "gif".into(),
                description: "GIF87a".into(),
                offset: 0,
                magic: b"GIF87a".to_vec(),
                is_aligned: false,
            },
            FileSignature {
                extension: "gif".into(),
                description: "GIF89a".into(),
                offset: 0,
                magic: b"GIF89a".to_vec(),
                is_aligned: false,
            },
        ],
    );

    sigs.insert(
        "pdf",
        vec![FileSignature {
            extension: "pdf".into(),
            description: "PDF".into(),
            offset: 0,
            magic: b"%PDF".to_vec(),
            is_aligned: false,
        }],
    );

    sigs.insert(
        "zip",
        vec![
            FileSignature {
                extension: "zip".into(),
                description: "ZIP".into(),
                offset: 0,
                magic: vec![0x50, 0x4B, 0x03, 0x04],
                is_aligned: false,
            },
            FileSignature {
                extension: "zip".into(),
                description: "ZIP empty".into(),
                offset: 0,
                magic: vec![0x50, 0x4B, 0x05, 0x06],
                is_aligned: false,
            },
        ],
    );

    sigs.insert(
        "doc",
        vec![FileSignature {
            extension: "doc".into(),
            description: "MS Office (old)".into(),
            offset: 0,
            magic: vec![0xD0, 0xCF, 0x11, 0xE0],
            is_aligned: false,
        }],
    );

    sigs.insert(
        "docx",
        vec![FileSignature {
            extension: "docx".into(),
            description: "Office Open XML".into(),
            offset: 0,
            magic: vec![0x50, 0x4B, 0x03, 0x04],
            is_aligned: false,
        }],
    );

    sigs.insert(
        "exe",
        vec![FileSignature {
            extension: "exe".into(),
            description: "DOS MZ EXE".into(),
            offset: 0,
            magic: vec![0x4D, 0x5A],
            is_aligned: false,
        }],
    );

    sigs.insert(
        "dll",
        vec![FileSignature {
            extension: "dll".into(),
            description: "Windows DLL".into(),
            offset: 0,
            magic: vec![0x4D, 0x5A],
            is_aligned: false,
        }],
    );

    sigs.insert(
        "mp3",
        vec![
            FileSignature {
                extension: "mp3".into(),
                description: "MP3".into(),
                offset: 0,
                magic: vec![0xFF, 0xFB],
                is_aligned: false,
            },
            FileSignature {
                extension: "mp3".into(),
                description: "MP3".into(),
                offset: 0,
                magic: vec![0xFF, 0xF3],
                is_aligned: false,
            },
            FileSignature {
                extension: "mp3".into(),
                description: "MP3".into(),
                offset: 0,
                magic: vec![0xFF, 0xF2],
                is_aligned: false,
            },
            FileSignature {
                extension: "mp3".into(),
                description: "ID3".into(),
                offset: 0,
                magic: b"ID3".to_vec(),
                is_aligned: false,
            },
        ],
    );

    sigs.insert(
        "mp4",
        vec![FileSignature {
            extension: "mp4".into(),
            description: "MP4".into(),
            offset: 4,
            magic: b"ftyp".to_vec(),
            is_aligned: false,
        }],
    );

    sigs.insert(
        "avi",
        vec![FileSignature {
            extension: "avi".into(),
            description: "AVI".into(),
            offset: 0,
            magic: b"RIFF".to_vec(),
            is_aligned: false,
        }],
    );

    sigs.insert(
        "wav",
        vec![FileSignature {
            extension: "wav".into(),
            description: "WAV".into(),
            offset: 0,
            magic: b"RIFF".to_vec(),
            is_aligned: false,
        }],
    );

    sigs.insert(
        "bmp",
        vec![FileSignature {
            extension: "bmp".into(),
            description: "BMP".into(),
            offset: 0,
            magic: vec![0x42, 0x4D],
            is_aligned: false,
        }],
    );

    sigs.insert(
        "ico",
        vec![FileSignature {
            extension: "ico".into(),
            description: "ICO".into(),
            offset: 0,
            magic: vec![0x00, 0x00, 0x01, 0x00],
            is_aligned: false,
        }],
    );

    sigs.insert(
        "rar",
        vec![FileSignature {
            extension: "rar".into(),
            description: "RAR".into(),
            offset: 0,
            magic: vec![0x52, 0x61, 0x72, 0x21],
            is_aligned: false,
        }],
    );

    sigs.insert(
        "7z",
        vec![FileSignature {
            extension: "7z".into(),
            description: "7-Zip".into(),
            offset: 0,
            magic: vec![0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C],
            is_aligned: false,
        }],
    );

    sigs.insert(
        "gz",
        vec![FileSignature {
            extension: "gz".into(),
            description: "GZIP".into(),
            offset: 0,
            magic: vec![0x1F, 0x8B],
            is_aligned: false,
        }],
    );

    sigs.insert(
        "tar",
        vec![FileSignature {
            extension: "tar".into(),
            description: "POSIX tar".into(),
            offset: 0,
            magic: b"ustar".to_vec(),
            is_aligned: false,
        }],
    );

    sigs.insert(
        "iso",
        vec![FileSignature {
            extension: "iso".into(),
            description: "ISO 9660".into(),
            offset: 0x8001,
            magic: b"CD001".to_vec(),
            is_aligned: true,
        }],
    );

    sigs
}

#[derive(Debug)]
pub struct FileTypeMatch {
    pub extension: String,
    pub description: String,
    pub offset: u64,
}

pub fn detect_file_type(data: &[u8]) -> Vec<FileTypeMatch> {
    let sigs = get_known_signatures();
    let mut matches = Vec::new();

    for ext_sigs in sigs.values() {
        for sig in ext_sigs {
            let offset = sig.offset as usize;
            if offset + sig.magic.len() <= data.len()
                && data[offset..offset + sig.magic.len()] == sig.magic[..]
            {
                matches.push(FileTypeMatch {
                    extension: sig.extension.clone(),
                    description: sig.description.clone(),
                    offset: sig.offset,
                });
            }
        }
    }

    matches
}
