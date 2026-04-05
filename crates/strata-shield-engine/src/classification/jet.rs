use crate::errors::ForensicError;
use serde_json::Value;
use std::env;
use std::path::Path;
use std::path::PathBuf;

#[derive(Debug, Clone, Default)]
pub struct JetDatabase {
    pub path: String,
    pub format_version: u16,
    pub database_page_size: u16,
    pub tables: Vec<JetTable>,
}

#[derive(Debug, Clone, Default)]
pub struct JetTable {
    pub name: String,
    pub record_count: u32,
    pub pages: u32,
    pub columns: Vec<JetColumn>,
    pub indexes: Vec<JetIndex>,
}

#[derive(Debug, Clone, Default)]
pub struct JetColumn {
    pub name: String,
    pub col_type: JetColumnType,
    pub size: u32,
    pub is_nullable: bool,
    pub is_autoincrement: bool,
}

#[derive(Debug, Clone, Default)]
pub enum JetColumnType {
    #[default]
    Unknown,
    Short,
    Long,
    Float,
    Double,
    Currency,
    DateTime,
    Binary,
    Text,
    LongBinary,
    LongText,
    UnsignedShort,
    UnsignedLong,
}

#[derive(Debug, Clone, Default)]
pub struct JetIndex {
    pub name: String,
    pub columns: Vec<String>,
    pub is_unique: bool,
    pub is_primary: bool,
}

#[derive(Debug, Clone, Default)]
pub struct JetQueryResult {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<JetValue>>,
    pub row_count: usize,
}

#[derive(Debug, Clone, Default)]
pub enum JetValue {
    #[default]
    Null,
    Short(i16),
    Long(i32),
    Float(f32),
    Double(f64),
    Currency(i64),
    DateTime(u64),
    Binary(Vec<u8>),
    Text(String),
}

pub fn open_jet_db(path: &Path) -> Result<JetDatabase, ForensicError> {
    let db = JetDatabase {
        path: path.to_string_lossy().to_string(),
        format_version: 0,
        database_page_size: 4096,
        tables: vec![],
    };
    Ok(db)
}

pub fn get_jet_tables(db: &JetDatabase) -> Vec<JetTable> {
    db.tables.clone()
}

pub fn get_jet_table_record_count(db: &JetDatabase, table_name: &str) -> u32 {
    db.tables
        .iter()
        .find(|t| t.name == table_name)
        .map(|t| t.record_count)
        .unwrap_or(0)
}

pub fn execute_jet_query(
    _db: &JetDatabase,
    _table_name: &str,
    _columns: Option<&[String]>,
) -> Result<JetQueryResult, ForensicError> {
    Ok(JetQueryResult {
        columns: vec![],
        rows: vec![],
        row_count: 0,
    })
}

pub fn get_jet_indexes(db: &JetDatabase, table_name: &str) -> Vec<JetIndex> {
    db.tables
        .iter()
        .find(|t| t.name == table_name)
        .map(|t| t.indexes.clone())
        .unwrap_or_default()
}

pub fn detect_jet_database(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    let signature = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    signature == 0x00006E06 || signature == 0x00000001
}

pub fn extract_jet_catalog(db: &JetDatabase) -> Result<Vec<JetCatalogEntry>, ForensicError> {
    let from_env = env::var("FORENSIC_JET_CATALOG").map(PathBuf::from).ok();
    let fallback = PathBuf::from(format!("{}.catalog.json", db.path));
    let Some(items) = load(from_env.unwrap_or(fallback)) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .map(|v| JetCatalogEntry {
            object_type: s(&v, &["object_type", "type"]),
            object_name: s(&v, &["object_name", "name"]),
            owner: s(&v, &["owner"]),
            create_date: opt_n(&v, &["create_date", "created"]),
        })
        .filter(|x| !x.object_name.is_empty() || !x.object_type.is_empty())
        .collect())
}

#[derive(Debug, Clone, Default)]
pub struct JetCatalogEntry {
    pub object_type: String,
    pub object_name: String,
    pub owner: String,
    pub create_date: Option<u64>,
}

pub fn get_jet_column_value(_record: &[u8], _column: &JetColumn) -> Option<JetValue> {
    Some(JetValue::Null)
}

pub fn parse_jet_pages(
    db: &JetDatabase,
    page_numbers: &[u32],
) -> Result<Vec<JetPage>, ForensicError> {
    let from_env = env::var("FORENSIC_JET_PAGES").map(PathBuf::from).ok();
    let fallback = PathBuf::from(format!("{}.pages.json", db.path));
    let Some(items) = load(from_env.unwrap_or(fallback)) else {
        return Ok(Vec::new());
    };
    Ok(items
        .into_iter()
        .filter(|v| {
            let page = n(v, &["page_number", "number"]) as u32;
            page_numbers.is_empty() || page_numbers.contains(&page)
        })
        .map(|v| JetPage {
            page_number: n(&v, &["page_number", "number"]) as u32,
            page_type: page_type_enum(s(&v, &["page_type", "type"])),
            data: bytes_from_value(v.get("data")),
        })
        .collect())
}

#[derive(Debug, Clone, Default)]
pub struct JetPage {
    pub page_number: u32,
    pub page_type: JetPageType,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub enum JetPageType {
    #[default]
    Unknown,
    Database,
    Table,
    Index,
    LongValue,
}

pub fn repair_jet_database(db_path: &Path) -> Result<JetDatabase, ForensicError> {
    open_jet_db(db_path)
}

fn page_type_enum(value: String) -> JetPageType {
    match value.to_ascii_lowercase().as_str() {
        "database" => JetPageType::Database,
        "table" => JetPageType::Table,
        "index" => JetPageType::Index,
        "longvalue" | "long_value" => JetPageType::LongValue,
        _ => JetPageType::Unknown,
    }
}

fn load(path: PathBuf) -> Option<Vec<Value>> {
    let data = super::scalpel::read_prefix(&path, super::scalpel::DEFAULT_BINARY_MAX_BYTES).ok()?;
    let v: Value = serde_json::from_slice(&data).ok()?;
    if let Some(items) = v.as_array() {
        Some(items.clone())
    } else if v.is_object() {
        v.get("items")
            .and_then(Value::as_array)
            .cloned()
            .or_else(|| v.get("results").and_then(Value::as_array).cloned())
            .or_else(|| Some(vec![v]))
    } else {
        None
    }
}

fn bytes_from_value(value: Option<&Value>) -> Vec<u8> {
    match value {
        Some(Value::String(s)) => s.as_bytes().to_vec(),
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_u64)
            .filter(|x| *x <= 255)
            .map(|x| x as u8)
            .collect(),
        _ => Vec::new(),
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
    opt_n(v, keys).unwrap_or(0)
}

fn opt_n(v: &Value, keys: &[&str]) -> Option<u64> {
    for k in keys {
        if let Some(x) = v.get(*k).and_then(Value::as_u64) {
            return Some(x);
        }
        if let Some(x) = v.get(*k).and_then(Value::as_i64) {
            if x >= 0 {
                return Some(x as u64);
            }
        }
        if let Some(x) = v.get(*k).and_then(Value::as_str) {
            if let Ok(n) = x.parse::<u64>() {
                return Some(n);
            }
        }
    }
    None
}
