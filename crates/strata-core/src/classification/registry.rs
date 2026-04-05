use std::path::Path;

#[derive(Debug, Clone)]
pub struct RegistryKey {
    pub name: String,
    pub path: String,
    pub values: Vec<RegistryValue>,
}

#[derive(Debug, Clone)]
pub struct RegistryValue {
    pub name: String,
    pub value_type: RegistryValueType,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum RegistryValueType {
    String,
    ExpandString,
    Binary,
    DWord,
    QWord,
    MultiString,
    Unknown,
}

pub fn parse_ntuser_dat(path: &Path) -> Result<Vec<RegistryKey>, std::io::Error> {
    let mut keys = Vec::new();

    if !path.exists() {
        return Ok(keys);
    }

    let data = super::scalpel::read_prefix(path, super::scalpel::DEFAULT_BINARY_MAX_BYTES)?;

    if data.len() < 512 {
        return Ok(keys);
    }

    if data[0..4] == b"regf"[..] {
        keys.push(RegistryKey {
            name: "NTUSER.DAT".to_string(),
            path: path.display().to_string(),
            values: Vec::new(),
        });
    }

    Ok(keys)
}

pub fn parse_sam_database(path: &Path) -> Result<Vec<RegistryKey>, std::io::Error> {
    let mut keys = Vec::new();

    if !path.exists() {
        return Ok(keys);
    }

    let data = super::scalpel::read_prefix(path, super::scalpel::DEFAULT_BINARY_MAX_BYTES)?;

    if data.len() < 512 {
        return Ok(keys);
    }

    if data[0..4] == b"regf"[..] {
        keys.push(RegistryKey {
            name: "SAM".to_string(),
            path: path.display().to_string(),
            values: Vec::new(),
        });
    }

    Ok(keys)
}

pub fn parse_system_registry(path: &Path) -> Result<Vec<RegistryKey>, std::io::Error> {
    let mut keys = Vec::new();

    if !path.exists() {
        return Ok(keys);
    }

    let data = super::scalpel::read_prefix(path, super::scalpel::DEFAULT_BINARY_MAX_BYTES)?;

    if data.len() < 512 {
        return Ok(keys);
    }

    if data[0..4] == b"regf"[..] {
        keys.push(RegistryKey {
            name: "SYSTEM".to_string(),
            path: path.display().to_string(),
            values: Vec::new(),
        });
    }

    Ok(keys)
}

pub fn extract_user_accounts(base_path: &Path) -> Vec<String> {
    let mut users = Vec::new();

    let users_path = base_path.join("Users");
    if let Ok(entries) = std::fs::read_dir(&users_path) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if let Some(name) = path.file_name() {
                    let name_str = name.to_string_lossy();
                    if !name_str.starts_with('.') && name_str != "Public" {
                        users.push(name_str.to_string());
                    }
                }
            }
        }
    }

    users
}
