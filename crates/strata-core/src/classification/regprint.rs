use std::path::Path;

use super::reg_export::{decode_reg_string, default_reg_path, key_leaf, load_reg_records};

pub fn get_printers() -> Vec<PrinterReg> {
    get_printers_from_reg(&default_reg_path("print.reg"))
}

pub fn get_printers_from_reg(path: &Path) -> Vec<PrinterReg> {
    let records = load_reg_records(path);
    let mut out = Vec::new();

    for record in records.iter().filter(|r| {
        r.path
            .to_ascii_lowercase()
            .contains("\\control\\print\\printers\\")
    }) {
        out.push(PrinterReg {
            name: key_leaf(&record.path),
            port: record
                .values
                .get("Port")
                .and_then(|v| decode_reg_string(v))
                .unwrap_or_default(),
            driver: record
                .values
                .get("PrinterDriver")
                .and_then(|v| decode_reg_string(v))
                .unwrap_or_default(),
            server: record
                .values
                .get("Server")
                .and_then(|v| decode_reg_string(v)),
        });
    }

    out
}

#[derive(Debug, Clone, Default)]
pub struct PrinterReg {
    pub name: String,
    pub port: String,
    pub driver: String,
    pub server: Option<String>,
}

pub fn get_print_connector() -> Vec<PrintConnector> {
    get_print_connector_from_reg(&default_reg_path("print.reg"))
}

pub fn get_print_connector_from_reg(path: &Path) -> Vec<PrintConnector> {
    let records = load_reg_records(path);
    let mut out = Vec::new();

    for record in records.iter().filter(|r| {
        r.path
            .to_ascii_lowercase()
            .contains("\\print\\connections\\")
    }) {
        out.push(PrintConnector {
            name: key_leaf(&record.path),
            url: record
                .values
                .get("Server")
                .and_then(|v| decode_reg_string(v))
                .unwrap_or_default(),
        });
    }

    out
}

#[derive(Debug, Clone, Default)]
pub struct PrintConnector {
    pub name: String,
    pub url: String,
}

pub fn get_fax_history() -> Vec<FaxEntry> {
    get_fax_history_from_reg(&default_reg_path("print.reg"))
}

pub fn get_fax_history_from_reg(path: &Path) -> Vec<FaxEntry> {
    let records = load_reg_records(path);
    let mut out = Vec::new();
    for record in records
        .iter()
        .filter(|r| r.path.to_ascii_lowercase().contains("\\fax\\"))
    {
        for raw in record.values.values() {
            if let Some(recipient) = decode_reg_string(raw) {
                out.push(FaxEntry {
                    recipient,
                    timestamp: None,
                });
            }
        }
    }
    out
}

#[derive(Debug, Clone, Default)]
pub struct FaxEntry {
    pub recipient: String,
    pub timestamp: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parse_printer_registry_values() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("print.reg");
        strata_fs::write(
            &file,
            r#"
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print\Printers\OfficePrinter]
"Port"="IP_10.0.0.15"
"PrinterDriver"="HP Universal Printing"
"#,
        )
        .unwrap();
        let rows = get_printers_from_reg(&file);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "OfficePrinter");
    }
}
