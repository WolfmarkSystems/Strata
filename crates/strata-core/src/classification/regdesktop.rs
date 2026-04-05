use std::path::Path;

use super::reg_export::{decode_reg_string, default_reg_path, load_reg_records, parse_reg_u32};

pub fn get_desktop_wallpaper() -> WallpaperInfo {
    get_desktop_wallpaper_from_reg(&default_reg_path("desktop.reg"))
}

pub fn get_desktop_wallpaper_from_reg(path: &Path) -> WallpaperInfo {
    let records = load_reg_records(path);
    if let Some(record) = records.iter().find(|r| {
        r.path
            .to_ascii_lowercase()
            .contains("\\control panel\\desktop")
    }) {
        WallpaperInfo {
            wallpaper: record
                .values
                .get("Wallpaper")
                .and_then(|v| decode_reg_string(v))
                .unwrap_or_default(),
            style: record
                .values
                .get("WallpaperStyle")
                .and_then(|v| decode_reg_string(v))
                .unwrap_or_default(),
            tile_wallpaper: record
                .values
                .get("TileWallpaper")
                .and_then(|v| parse_reg_u32(v))
                .unwrap_or(0)
                != 0,
        }
    } else {
        WallpaperInfo::default()
    }
}

#[derive(Debug, Clone, Default)]
pub struct WallpaperInfo {
    pub wallpaper: String,
    pub style: String,
    pub tile_wallpaper: bool,
}

pub fn get_control_panel() -> Vec<ControlPanelItem> {
    get_control_panel_from_reg(&default_reg_path("desktop.reg"))
}

pub fn get_control_panel_from_reg(path: &Path) -> Vec<ControlPanelItem> {
    let records = load_reg_records(path);
    let mut out = Vec::new();
    for record in records.iter().filter(|r| {
        r.path
            .to_ascii_lowercase()
            .contains("\\control panel\\cpls")
    }) {
        for (name, raw) in &record.values {
            if let Some(value) = decode_reg_string(raw) {
                out.push(ControlPanelItem {
                    name: name.clone(),
                    canonical_name: value,
                });
            }
        }
    }
    out
}

#[derive(Debug, Clone, Default)]
pub struct ControlPanelItem {
    pub name: String,
    pub canonical_name: String,
}

pub fn get_printer_ports() -> Vec<PrinterPort> {
    get_printer_ports_from_reg(&default_reg_path("desktop.reg"))
}

pub fn get_printer_ports_from_reg(path: &Path) -> Vec<PrinterPort> {
    let records = load_reg_records(path);
    let mut out = Vec::new();
    for record in records
        .iter()
        .filter(|r| r.path.to_ascii_lowercase().contains("\\printers\\ports"))
    {
        for (name, raw) in &record.values {
            if let Some(host) = decode_reg_string(raw) {
                out.push(PrinterPort {
                    name: name.clone(),
                    host: host.clone(),
                    protocol: infer_protocol(&host),
                });
            }
        }
    }
    out
}

#[derive(Debug, Clone, Default)]
pub struct PrinterPort {
    pub name: String,
    pub host: String,
    pub protocol: String,
}

fn infer_protocol(host: &str) -> String {
    if host.to_ascii_lowercase().starts_with("http") {
        "http".to_string()
    } else if host.to_ascii_lowercase().starts_with("\\\\") {
        "smb".to_string()
    } else {
        "raw".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parse_desktop_wallpaper() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("desktop.reg");
        strata_fs::write(
            &file,
            r#"
[HKEY_CURRENT_USER\Control Panel\Desktop]
"Wallpaper"="C:\Wallpapers\corp.jpg"
"WallpaperStyle"="10"
"TileWallpaper"=dword:00000000
"#,
        )
        .unwrap();
        let w = get_desktop_wallpaper_from_reg(&file);
        assert_eq!(w.wallpaper, "C:\\Wallpapers\\corp.jpg");
    }
}
