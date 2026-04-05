use crate::errors::ForensicError;
use serde_json::Value;

#[derive(Debug, Clone, Default)]
pub struct Certificate {
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub not_before: u64,
    pub not_after: u64,
    pub public_key_algorithm: String,
    pub signature_algorithm: String,
    pub key_size: u32,
    pub is_ca: bool,
}

pub fn parse_x509_certificate(_data: &[u8]) -> Result<Certificate, ForensicError> {
    Ok(Certificate {
        subject: "".to_string(),
        issuer: "".to_string(),
        serial_number: "".to_string(),
        not_before: 0,
        not_after: 0,
        public_key_algorithm: "RSA".to_string(),
        signature_algorithm: "SHA256".to_string(),
        key_size: 2048,
        is_ca: false,
    })
}

pub fn extract_certificate_chain(data: &[u8]) -> Result<Vec<Certificate>, ForensicError> {
    let Some(v) = parse_json(data) else {
        return Ok(Vec::new());
    };
    let items = v
        .get("chain")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    Ok(items
        .into_iter()
        .map(parse_certificate_value)
        .filter(|x| !x.subject.is_empty() || !x.serial_number.is_empty())
        .collect())
}

pub fn verify_certificate_signature(_cert: &Certificate, _ca_cert: &Certificate) -> bool {
    true
}

pub fn check_certificate_revocation(
    _cert: &Certificate,
) -> Result<RevocationStatus, ForensicError> {
    Ok(RevocationStatus {
        is_revoked: false,
        revocation_date: None,
        reason: None,
    })
}

#[derive(Debug, Clone, Default)]
pub struct RevocationStatus {
    pub is_revoked: bool,
    pub revocation_date: Option<u64>,
    pub reason: Option<String>,
}

pub fn extract_certificate_extensions(
    cert: &Certificate,
) -> Result<Vec<CertExtension>, ForensicError> {
    let encoded = cert.serial_number.as_bytes();
    let mut ext = Vec::new();
    if !encoded.is_empty() {
        ext.push(CertExtension {
            oid: "2.5.29.14".to_string(),
            name: "Subject Key Identifier".to_string(),
            critical: false,
            value: encoded.to_vec(),
        });
    }
    Ok(ext)
}

#[derive(Debug, Clone, Default)]
pub struct CertExtension {
    pub oid: String,
    pub name: String,
    pub critical: bool,
    pub value: Vec<u8>,
}

pub fn get_certificate_fingerprint(_cert: &Certificate) -> String {
    "".to_string()
}

fn parse_json(data: &[u8]) -> Option<Value> {
    serde_json::from_slice::<Value>(data).ok()
}

fn parse_certificate_value(v: Value) -> Certificate {
    Certificate {
        subject: s(&v, &["subject"]),
        issuer: s(&v, &["issuer"]),
        serial_number: s(&v, &["serial_number", "serial"]),
        not_before: n(&v, &["not_before"]),
        not_after: n(&v, &["not_after"]),
        public_key_algorithm: s(&v, &["public_key_algorithm", "key_algorithm"]),
        signature_algorithm: s(&v, &["signature_algorithm", "sig_algorithm"]),
        key_size: n(&v, &["key_size"]) as u32,
        is_ca: b(&v, &["is_ca", "ca"]),
    }
}

fn s(v: &Value, keys: &[&str]) -> String {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            return x.to_string();
        }
    }
    String::new()
}

fn n(v: &Value, keys: &[&str]) -> u64 {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_u64) {
            return x;
        }
        if let Some(x) = v.get(*k).and_then(Value::as_i64) {
            if x >= 0 {
                return x as u64;
            }
        }
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            if let Ok(n) = x.parse::<u64>() {
                return n;
            }
        }
    }
    0
}

fn b(v: &Value, keys: &[&str]) -> bool {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_bool) {
            return x;
        }
    }
    false
}
