use plist::Value;
use std::io::Cursor;
use std::path::Path;
use strata_core::parser::ParserError;

pub(crate) fn parse_plist_data(data: &[u8]) -> Result<Value, ParserError> {
    if data.is_empty() {
        return Err(ParserError::Parse("Empty plist data".to_string()));
    }

    // plist crate automatically handles XML and Binary formats
    Value::from_reader(Cursor::new(data))
        .map_err(|e| ParserError::Parse(format!("Failed to parse plist: {}", e)))
}

#[allow(dead_code)]
pub(crate) fn parse_plist_file(path: &Path) -> Result<Value, ParserError> {
    Value::from_file(path)
        .map_err(|e| ParserError::Parse(format!("Failed to read plist file {:?}: {}", path, e)))
}

/// Helper to get a string from a plist dictionary
pub(crate) fn get_string_from_plist(value: &Value, key: &str) -> Option<String> {
    value
        .as_dictionary()
        .and_then(|dict| dict.get(key))
        .and_then(|val| val.as_string())
        .map(|s| s.to_string())
}

/// Helper to get a boolean from a plist dictionary
pub(crate) fn get_bool_from_plist(value: &Value, key: &str) -> Option<bool> {
    value
        .as_dictionary()
        .and_then(|dict| dict.get(key))
        .and_then(|val| val.as_boolean())
}

/// Helper to get an integer from a plist dictionary
pub(crate) fn get_int_from_plist(value: &Value, key: &str) -> Option<i64> {
    value
        .as_dictionary()
        .and_then(|dict| dict.get(key))
        .and_then(|val| {
            val.as_unsigned_integer()
                .map(|i| i as i64)
                .or_else(|| val.as_signed_integer())
        })
}
