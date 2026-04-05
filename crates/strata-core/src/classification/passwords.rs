use crate::errors::ForensicError;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct PasswordPolicy {
    pub min_length: u32,
    pub max_length: u32,
    pub complexity_required: bool,
    pub history_count: u32,
    pub max_age_days: u32,
    pub min_age_days: u32,
    pub lockout_threshold: u32,
    pub lockout_duration_minutes: u32,
}

pub fn parse_local_security_policy(base_path: &Path) -> Result<PasswordPolicy, ForensicError> {
    let policy_path = base_path.join("SECURITY").join("Policy");

    let policy = PasswordPolicy {
        min_length: 0,
        max_length: 0,
        complexity_required: false,
        history_count: 0,
        max_age_days: 0,
        min_age_days: 0,
        lockout_threshold: 0,
        lockout_duration_minutes: 0,
    };

    if policy_path.exists() {
        if let Ok(data) =
            super::scalpel::read_prefix(&policy_path, super::scalpel::DEFAULT_BINARY_MAX_BYTES)
        {
            return parse_security_policy_data(&data, policy);
        }
    }

    Ok(policy)
}

fn parse_security_policy_data(
    data: &[u8],
    mut policy: PasswordPolicy,
) -> Result<PasswordPolicy, ForensicError> {
    let mut offset = 0;

    while offset + 8 <= data.len() {
        let section = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        let size = u32::from_le_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);

        if size == 0 || offset + size as usize > data.len() {
            break;
        }

        match section {
            0x00000001 => {
                policy.min_length = size;
            }
            0x00000002 => {
                policy.max_length = size;
            }
            0x00000004 => {
                policy.complexity_required = size > 0;
            }
            0x00000008 => {
                policy.history_count = size;
            }
            _ => {}
        }

        offset += size as usize;
    }

    Ok(policy)
}

pub fn check_password_strength(password: &str) -> PasswordStrength {
    let length = password.len() as u32;
    let mut score = 0;

    if length >= 8 {
        score += 1;
    }
    if length >= 12 {
        score += 1;
    }
    if length >= 16 {
        score += 1;
    }

    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| !c.is_alphanumeric());

    if has_lower {
        score += 1;
    }
    if has_upper {
        score += 1;
    }
    if has_digit {
        score += 1;
    }
    if has_special {
        score += 1;
    }

    let common_passwords = [
        "password", "123456", "qwerty", "admin", "letmein", "welcome",
    ];
    if common_passwords
        .iter()
        .any(|p| password.to_lowercase().contains(p))
    {
        return PasswordStrength::VeryWeak;
    }

    match score {
        0..=2 => PasswordStrength::VeryWeak,
        3..=4 => PasswordStrength::Weak,
        5..=6 => PasswordStrength::Medium,
        _ => PasswordStrength::Strong,
    }
}

#[derive(Debug, Clone)]
pub enum PasswordStrength {
    VeryWeak,
    Weak,
    Medium,
    Strong,
    VeryStrong,
}
