use std::collections::HashSet;
use std::path::{Path, PathBuf};

use rusqlite::OpenFlags;
use strata_plugin_sdk::{
    Artifact, ArtifactCategory, ArtifactRecord, ForensicValue, PluginCapability, PluginContext,
    PluginOutput, PluginResult, PluginSummary, PluginType, StrataPlugin,
};

pub struct ChroniclePlugin {
    name: String,
    version: String,
}

impl Default for ChroniclePlugin {
    fn default() -> Self {
        Self::new()
    }
}

const SUSPICIOUS_DOMAINS: &[&str] = &["pastebin.com", "mega.nz", "transfer.sh", ".onion", "ngrok.io"];

impl ChroniclePlugin {
    pub fn new() -> Self {
        Self { name: "Strata Chronicle".to_string(), version: "2.0.0".to_string() }
    }

    fn classify_file(path: &Path) -> Option<(&'static str, &'static str)> {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        match ext.to_lowercase().as_str() {
            "pf" => Some(("Prefetch", "System Activity")),
            "lnk" => Some(("LNK Shortcut", "User Activity")),
            "evtx" => Some(("Windows Event Log", "System Activity")),
            _ => {
                let lower = name.to_lowercase();
                if lower == "history" || lower == "places.sqlite" { Some(("Browser History", "User Activity")) } else { None }
            }
        }
    }

    fn is_suspicious_path(path: &Path) -> bool {
        let path_str = path.to_string_lossy().to_lowercase();
        path_str.contains("temp") || path_str.contains("appdata")
    }

    fn is_suspicious_url(url: &str) -> bool {
        let lower = url.to_lowercase();
        for domain in SUSPICIOUS_DOMAINS { if lower.contains(domain) { return true; } }
        if let Some(rest) = lower.strip_prefix("http://").or_else(|| lower.strip_prefix("https://")) {
            let host = rest.split('/').next().unwrap_or("");
            let host = host.split(':').next().unwrap_or("");
            let parts: Vec<&str> = host.split('.').collect();
            if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) { return true; }
        }
        false
    }

    fn parse_prefetch_content(path: &Path, data: &[u8]) -> Vec<(String, String, Option<i64>)> {
        let mut results = Vec::new();
        if data.len() < 84 { return results; }
        if data.len() >= 8 && &data[0..3] == b"MAM" && data[3] == 0x04 {
            let fname = path.file_stem().and_then(|s| s.to_str()).unwrap_or("unknown");
            results.push((format!("{} executed (compressed)", fname), "Compressed prefetch (MAM\\x04), version info in header only".to_string(), None));
            return results;
        }
        let version = u32::from_le_bytes(data[0..4].try_into().unwrap_or([0; 4]));
        let version_label = match version { 17 => "XP", 23 => "Vista/7", 26 => "Win8", 30 => "Win10", _ => "Unknown" };
        let exe_name = if data.len() >= 76 {
            let name_bytes = &data[16..76];
            let u16s: Vec<u16> = name_bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&ch| ch != 0).collect();
            String::from_utf16_lossy(&u16s)
        } else { path.file_stem().and_then(|s| s.to_str()).unwrap_or("unknown").to_string() };
        let exe_display = if exe_name.is_empty() { path.file_stem().and_then(|s| s.to_str()).unwrap_or("unknown").to_string() } else { exe_name };
        let run_count = match version {
            17 if data.len() >= 20 => u32::from_le_bytes(data[16..20].try_into().unwrap_or([0; 4])),
            23 if data.len() >= 156 => u32::from_le_bytes(data[152..156].try_into().unwrap_or([0; 4])),
            26 | 30 if data.len() >= 212 => u32::from_le_bytes(data[208..212].try_into().unwrap_or([0; 4])),
            _ => 0,
        };
        let run_times: Vec<i64> = match version {
            17 if data.len() >= 0x80 => vec![i64::from_le_bytes(data[0x78..0x80].try_into().unwrap_or([0; 8]))],
            23 if data.len() >= 136 => vec![i64::from_le_bytes(data[128..136].try_into().unwrap_or([0; 8]))],
            26 | 30 => { let mut t = Vec::new(); for i in 0..8 { let s = 0x80+i*8; let e = s+8; if data.len() < e { break; } let ft = i64::from_le_bytes(data[s..e].try_into().unwrap_or([0;8])); if ft > 0 { t.push(ft); } } t }
            _ => Vec::new(),
        };
        if run_times.is_empty() {
            results.push((format!("{} executed", exe_display), format!("Run count: {} | Prefetch v{} ({})", run_count, version, version_label), None));
        } else {
            for (i, ft) in run_times.iter().enumerate() {
                results.push((format!("{} executed", exe_display), format!("Run {} of {} | Prefetch v{} ({})", i+1, run_count.max(run_times.len() as u32), version, version_label), filetime_to_unix(*ft)));
            }
        }
        results
    }

    fn parse_browser_history_sqlite(path: &Path) -> Vec<(String, String, Option<i64>)> {
        let mut results = Vec::new();
        let conn = match rusqlite::Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX) { Ok(c) => c, Err(_) => return results };
        if table_exists(&conn, "urls") {
            let mut stmt = match conn.prepare("SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 5000") { Ok(s) => s, Err(_) => return results };
            let rows = stmt.query_map([], |row| { Ok((row.get::<_,String>(0).unwrap_or_default(), row.get::<_,String>(1).unwrap_or_default(), row.get::<_,i64>(2).unwrap_or(0), row.get::<_,i64>(3).unwrap_or(0))) });
            if let Ok(rows) = rows { for row in rows.flatten() { let (url, title, vc, ct) = row; let us = if ct > 0 { Some((ct-11644473600000000)/1000000) } else { None }; let dt = if title.is_empty() { url.clone() } else { title }; let sus = Self::is_suspicious_url(&url); results.push((dt, format!("URL: {} | Visits: {}{}", url, vc, if sus { " [SUSPICIOUS]" } else { "" }), us)); } }
            return results;
        }
        if table_exists(&conn, "moz_places") {
            let mut stmt = match conn.prepare("SELECT url, title, visit_count, last_visit_date FROM moz_places WHERE visit_count > 0 ORDER BY last_visit_date DESC LIMIT 5000") { Ok(s) => s, Err(_) => return results };
            let rows = stmt.query_map([], |row| { Ok((row.get::<_,String>(0).unwrap_or_default(), row.get::<_,String>(1).unwrap_or_default(), row.get::<_,i64>(2).unwrap_or(0), row.get::<_,i64>(3).unwrap_or(0))) });
            if let Ok(rows) = rows { for row in rows.flatten() { let (url, title, vc, mt) = row; let us = if mt > 0 { Some(mt/1000000) } else { None }; let dt = if title.is_empty() { url.clone() } else { title }; let sus = Self::is_suspicious_url(&url); results.push((dt, format!("URL: {} | Visits: {}{}", url, vc, if sus { " [SUSPICIOUS]" } else { "" }), us)); } }
        }
        results
    }

    /// v1.1.0: Parse the Chromium Media History SQLite database. The
    /// `playbackSession` table records every video/audio playback the user
    /// performed in Chrome or Edge. Survives normal "Clear browsing data"
    /// operations on most browser versions.
    fn parse_media_history(path: &Path) -> Vec<Artifact> {
        let mut out = Vec::new();
        let path_str = path.to_string_lossy().to_string();
        let conn = match rusqlite::Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        ) {
            Ok(c) => c,
            Err(_) => return out,
        };
        if !table_exists(&conn, "playbackSession") {
            return out;
        }
        let mut stmt = match conn.prepare(
            "SELECT url, title, last_updated_time_s, watch_time_s, last_video_position_s
             FROM playbackSession
             ORDER BY last_updated_time_s DESC
             LIMIT 200",
        ) {
            Ok(s) => s,
            Err(_) => return out,
        };
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0).unwrap_or_default(),
                row.get::<_, String>(1).unwrap_or_default(),
                row.get::<_, i64>(2).unwrap_or(0),
                row.get::<_, i64>(3).unwrap_or(0),
                row.get::<_, i64>(4).unwrap_or(0),
            ))
        });
        if let Ok(rows) = rows {
            for row in rows.flatten() {
                let (url, title, ts_s, watch_s, _pos) = row;
                let title_disp = if title.is_empty() { url.clone() } else { title };
                let mut a = Artifact::new("Media History", &path_str);
                if ts_s > 0 {
                    a.timestamp = Some(ts_s as u64);
                }
                a.add_field("title", &format!("Media played: {}", title_disp));
                a.add_field(
                    "detail",
                    &format!(
                        "URL: {} | Watch time: {}s | Survives normal history clear",
                        url, watch_s
                    ),
                );
                a.add_field("file_type", "Media History");
                a.add_field("forensic_value", "Low");
                out.push(a);
            }
        }
        out
    }

    fn parse_lnk_content(path: &Path, data: &[u8]) -> Vec<(String, String, Option<i64>)> {
        let mut results = Vec::new();
        if data.len() < 0x4C || data[0..4] != [0x4C,0x00,0x00,0x00] { return results; }
        let flags = u32::from_le_bytes(data[0x14..0x18].try_into().unwrap_or([0;4]));
        let has_idlist = flags & 0x01 != 0;
        let has_linkinfo = flags & 0x02 != 0;
        let mod_ft = if data.len() >= 0x2C { i64::from_le_bytes(data[0x24..0x2C].try_into().unwrap_or([0;8])) } else { 0 };
        let mod_unix = filetime_to_unix(mod_ft);
        let target_size = if data.len() >= 0x38 { u32::from_le_bytes(data[0x34..0x38].try_into().unwrap_or([0;4])) } else { 0 };
        let mut target_path = String::new();
        let mut offset = 0x4C_usize;
        if has_idlist { if data.len() >= offset+2 { offset += 2 + u16::from_le_bytes(data[offset..offset+2].try_into().unwrap_or([0;2])) as usize; } else { offset = data.len(); } }
        if has_linkinfo && offset+4 <= data.len() {
            let lis = u32::from_le_bytes(data[offset..offset+4].try_into().unwrap_or([0;4])) as usize;
            if lis >= 28 && offset+lis <= data.len() { let li = &data[offset..offset+lis]; if li.len() >= 20 { let lbo = u32::from_le_bytes(li[16..20].try_into().unwrap_or([0;4])) as usize; if lbo > 0 && lbo < li.len() { let pb = &li[lbo..]; if let Some(end) = pb.iter().position(|&b| b==0) { target_path = String::from_utf8_lossy(&pb[..end]).to_string(); } } } }
        }
        let tf = if !target_path.is_empty() { Path::new(&target_path).file_name().and_then(|n| n.to_str()).unwrap_or(&target_path).to_string() } else { path.file_stem().and_then(|s| s.to_str()).unwrap_or("unknown").to_string() };
        let detail = if target_path.is_empty() { format!("Target: (unresolved) | Size: {} bytes", target_size) } else { format!("Target: {} | Size: {} bytes", target_path, target_size) };
        results.push((format!("LNK -> {}", tf), detail, mod_unix));
        results
    }

    fn detect_recent_docs(path: &str, name: &str) -> Vec<Artifact> {
        let mut a = Vec::new();
        if path.to_lowercase().contains("recentdocs") { let mut art = Artifact::new("Recent Document", path); art.add_field("title", name); art.add_field("detail", "Recently accessed document found in RecentDocs MRU"); art.add_field("file_type", "Recent Document"); a.push(art); }
        a
    }
    fn detect_typed_paths(path: &str, name: &str) -> Vec<Artifact> {
        let mut a = Vec::new();
        if path.to_lowercase().contains("typedpaths") { let mut art = Artifact::new("Typed Path", path); art.add_field("title", name); art.add_field("detail", "User manually navigated to this location"); art.add_field("file_type", "Typed Path"); art.add_field("forensic_value", "High"); a.push(art); }
        a
    }
    fn detect_word_wheel_query(path: &str, name: &str) -> Vec<Artifact> {
        let mut a = Vec::new();
        if path.to_lowercase().contains("wordwheelquery") { let mut art = Artifact::new("File Explorer Search", path); art.add_field("title", name); art.add_field("detail", "User search term found"); art.add_field("file_type", "File Explorer Search"); art.add_field("forensic_value", "High"); a.push(art); }
        a
    }
    fn detect_activities_cache(path: &str, name: &str) -> Vec<Artifact> {
        let mut artifacts = Vec::new();
        if !name.eq_ignore_ascii_case("ActivitiesCache.db") { return artifacts; }
        let conn = match rusqlite::Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX) { Ok(c) => c, Err(_) => { let mut a = Artifact::new("Windows Timeline", path); a.add_field("title", name); a.add_field("detail", "ActivitiesCache.db found but could not be opened"); a.add_field("file_type", "Windows Timeline"); artifacts.push(a); return artifacts; } };
        let mut stmt = match conn.prepare("SELECT AppId, ActivityType, StartTime, EndTime FROM Activity ORDER BY StartTime DESC LIMIT 1000") { Ok(s) => s, Err(_) => { let mut a = Artifact::new("Windows Timeline", path); a.add_field("title", name); a.add_field("detail", "ActivitiesCache.db found but query failed"); a.add_field("file_type", "Windows Timeline"); artifacts.push(a); return artifacts; } };
        let rows = stmt.query_map([], |row| { Ok((row.get::<_,String>(0).unwrap_or_default(), row.get::<_,i64>(1).unwrap_or(0), row.get::<_,String>(2).unwrap_or_default(), row.get::<_,String>(3).unwrap_or_default())) });
        match rows { Ok(rows) => { let mut count = 0; for row in rows.flatten() { let (ai, at, st, et) = row; let mut a = Artifact::new("Windows Timeline", path); a.add_field("title", &ai); a.add_field("detail", &format!("Activity type: {} | Start: {} | End: {}", at, st, et)); a.add_field("file_type", "Windows Timeline"); artifacts.push(a); count += 1; } if count == 0 { let mut a = Artifact::new("Windows Timeline", path); a.add_field("title", name); a.add_field("detail", "ActivitiesCache.db found but Activity table is empty"); a.add_field("file_type", "Windows Timeline"); artifacts.push(a); } } Err(_) => { let mut a = Artifact::new("Windows Timeline", path); a.add_field("title", name); a.add_field("detail", "ActivitiesCache.db found but could not read rows"); a.add_field("file_type", "Windows Timeline"); artifacts.push(a); } }
        artifacts
    }
    fn detect_capability_access(path: &str, name: &str) -> Vec<Artifact> {
        let mut a = Vec::new();
        let lower = path.to_lowercase();
        if lower.contains("capabilityaccessmanager") || lower.contains("consentstore") { let mut art = Artifact::new("Camera/Mic Access", path); art.add_field("title", name); art.add_field("detail", "Capability access record found"); art.add_field("file_type", "Camera/Mic Access"); art.add_field("forensic_value", "High"); a.push(art); }
        a
    }
    fn rot13(s: &str) -> String { s.chars().map(|c| match c { 'A'..='M' | 'a'..='m' => (c as u8 + 13) as char, 'N'..='Z' | 'n'..='z' => (c as u8 - 13) as char, _ => c }).collect() }
    fn detect_userassist(_path: &Path, name: &str, path_str: &str) -> Vec<Artifact> {
        let mut artifacts = Vec::new();
        let lp = path_str.to_lowercase();
        if lp.contains("userassist") { let ln = name.to_lowercase(); if ln == "ntuser.dat" || lp.contains("ntuser.dat") { let mut a = Artifact::new("UserAssist Execution", path_str); a.add_field("title", "UserAssist Registry Hive"); a.add_field("detail", "NTUSER.DAT hive with UserAssist entries"); a.add_field("file_type", "UserAssist Execution"); a.add_field("forensic_value", "Critical"); a.add_field("mitre", "T1204.002"); artifacts.push(a); } }
        let rot13_indicators = ["{PROQHPG", "HFOE", "Zvpebfbsg", "Jvaqbjf"];
        if rot13_indicators.iter().any(|p| name.contains(p)) { let decoded = Self::rot13(name); let mut a = Artifact::new("UserAssist Execution", path_str); a.add_field("title", &format!("UserAssist ROT13: {}", decoded)); a.add_field("detail", &format!("ROT13 encoded name decoded: {} -> {}", name, decoded)); a.add_field("file_type", "UserAssist Execution"); a.add_field("forensic_value", "Critical"); a.add_field("mitre", "T1204.002"); artifacts.push(a); }
        artifacts
    }
    fn detect_recentdocs_detailed(path: &Path, name: &str, path_str: &str) -> Vec<Artifact> {
        let _ = path; let mut artifacts = Vec::new(); let lp = path_str.to_lowercase();
        if !lp.contains("recentdocs") { return artifacts; }
        let has_ext = lp.rsplit("recentdocs").next().and_then(|rest| { let t = rest.trim_start_matches(['/','\\']).to_string(); if t.starts_with('.') { let e = t.split(['/','\\']).next().unwrap_or(""); if !e.is_empty() { Some(e.to_string()) } else { None } } else { None } });
        if let Some(ext) = has_ext { let mut a = Artifact::new("Recent Document Extension", path_str); a.add_field("title", &format!("RecentDocs {} MRU", ext)); a.add_field("detail", &format!("Extension-specific MRU: last 20 {} files opened", ext)); a.add_field("file_type", "Recent Document Extension"); a.add_field("forensic_value", "High"); artifacts.push(a); }
        else { let is_mru = name.parse::<u64>().is_ok() || name == "MRUListEx"; let title = if is_mru { format!("RecentDocs MRU: {}", name) } else { format!("RecentDocs: {}", name) }; let mut a = Artifact::new("Recent Document (MRU)", path_str); a.add_field("title", &title); a.add_field("detail", "RecentDocs MRU entry"); a.add_field("file_type", "Recent Document (MRU)"); a.add_field("forensic_value", "High"); artifacts.push(a); }
        artifacts
    }
    fn detect_jumplist(path: &Path, name: &str, path_str: &str) -> Vec<Artifact> {
        let _ = path; let mut artifacts = Vec::new(); let ln = name.to_lowercase();
        let is_auto = ln.ends_with(".automaticdestinations-ms"); let is_custom = ln.ends_with(".customdestinations-ms");
        if !is_auto && !is_custom { return artifacts; }
        let app_id = name.split('.').next().unwrap_or("unknown");
        let known: &[(&str,&str)] = &[("1b4dd67f29cb1962","Windows Explorer"),("5f7b5f1e01b83767","Internet Explorer"),("b91c07e03a5a0a35","Google Chrome"),("5d696d521de238c3","Google Chrome"),("9b9cdc69c1c24e2b","Mozilla Firefox"),("9c764ede09a2f88e","Microsoft Edge"),("a7bd71699cd38d1c","Microsoft Word"),("f0275e1002be10b2","Microsoft Excel"),("ee9f71d9828e153e","Microsoft Outlook"),("d00655d2aa12ff6d","Excel 2016+"),("b0459d4b0fb86a58","Notepad"),("2e61e3e1604d0de3","Paint"),("6ec72ce0fdc76d9e","Windows Media Player"),("3dc09a3a42e88c38","Adobe Reader"),("7494a606a9eef18e","Adobe Acrobat"),("64bc1e327c5f8b8a","7-Zip"),("a1c8b4d3e2f09175","VLC Media Player"),("f38b1c0d3e9a7625","Visual Studio Code"),("4975d6798a1a4326","VS Code"),("1bc392b8e104a00e","Remote Desktop"),("bcc705e07d55efb0","PuTTY")];
        let dn = known.iter().find(|(id,_)| id.eq_ignore_ascii_case(app_id)).map(|(_,n)| n.to_string()).unwrap_or_else(|| format!("Unknown App [{}]", app_id));
        let jt = if is_auto { "Automatic" } else { "Custom" };
        let mut a = Artifact::new("Jump List Entry", path_str); a.add_field("title", &format!("{} Jump List", dn)); a.add_field("detail", &format!("{} destinations file via {}. CFB/OLE2 format with DestList stream.", jt, dn)); a.add_field("file_type", "Jump List Entry"); a.add_field("forensic_value", "High"); a.add_field("mitre", "T1547.009"); artifacts.push(a);
        artifacts
    }

    /// GAP 1: Parse NTUSER.DAT registry hive for UserAssist and RecentDocs.
    fn parse_ntuser_dat(path: &Path, data: &[u8]) -> Vec<Artifact> {
        let mut artifacts = Vec::new();
        let path_str = path.to_string_lossy().to_string();
        let hive = match nt_hive::Hive::new(data) { Ok(h) => h, Err(_) => return artifacts };
        let root = match hive.root_key_node() { Ok(r) => r, Err(_) => return artifacts };
        // UserAssist
        let ua_node: Option<nt_hive::KeyNode<'_, &[u8]>> = (|| {
            root.subkey("Software")?.ok()?.subkey("Microsoft")?.ok()?.subkey("Windows")?.ok()?.subkey("CurrentVersion")?.ok()?.subkey("Explorer")?.ok()?.subkey("UserAssist")?.ok()
        })();
        if let Some(ua_node) = ua_node {
            if let Some(Ok(subkeys_iter)) = ua_node.subkeys() {
                for gkr in subkeys_iter {
                    let gk = match gkr { Ok(k) => k, Err(_) => continue };
                    let gn = match gk.name() { Ok(n) => n.to_string_lossy(), Err(_) => continue };
                    let gu = gn.to_uppercase();
                    let ut = if gu.contains("CEBFF5CD") { "Executable" } else if gu.contains("F4E57C4B") { "Shortcut" } else { continue };
                    let cn = match gk.subkey("Count") { Some(Ok(n)) => Some(n), _ => None };
                    if let Some(cn) = cn {
                        if let Some(Ok(vi)) = cn.values() {
                            for vr in vi {
                                let v = match vr { Ok(v) => v, Err(_) => continue };
                                let vn = match v.name() { Ok(n) => n.to_string_lossy(), Err(_) => continue };
                                let dn = Self::rot13(&vn);
                                let vd: Vec<u8> = match v.data() { Ok(d) => match d.into_vec() { Ok(v) => v, Err(_) => continue }, Err(_) => continue };
                                if vd.len() >= 72 {
                                    let rc = u32::from_le_bytes(vd[4..8].try_into().unwrap_or([0;4]));
                                    let fm = u32::from_le_bytes(vd[12..16].try_into().unwrap_or([0;4]));
                                    let ft = i64::from_le_bytes(vd[60..68].try_into().unwrap_or([0;8]));
                                    let us: Option<u64> = if ft > 116444736000000000 { Some(((ft-116444736000000000)/10000000) as u64) } else { None };
                                    let ts = us.map(|t| chrono::DateTime::from_timestamp(t as i64, 0).map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string()).unwrap_or_else(|| format!("unix:{}", t))).unwrap_or_else(|| "N/A".to_string());
                                    let mut a = Artifact::new("UserAssist Execution", &path_str); a.timestamp = us; a.add_field("title", &dn); a.add_field("detail", &format!("Runs: {} | Focus: {}ms | Last: {} | Type: {}", rc, fm, ts, ut)); a.add_field("file_type", "UserAssist Execution"); a.add_field("forensic_value", "Critical"); a.add_field("mitre", "T1204.002"); artifacts.push(a);
                                } else if !vd.is_empty() {
                                    let mut a = Artifact::new("UserAssist Execution", &path_str); a.add_field("title", &dn); a.add_field("detail", &format!("Type: {} | Data too short ({} bytes) for full parse", ut, vd.len())); a.add_field("file_type", "UserAssist Execution"); a.add_field("forensic_value", "High"); artifacts.push(a);
                                }
                            }
                        }
                    }
                }
            }
        }
        // RecentDocs
        let rd_node: Option<nt_hive::KeyNode<'_, &[u8]>> = (|| {
            root.subkey("Software")?.ok()?.subkey("Microsoft")?.ok()?.subkey("Windows")?.ok()?.subkey("CurrentVersion")?.ok()?.subkey("Explorer")?.ok()?.subkey("RecentDocs")?.ok()
        })();
        if let Some(rd_node) = rd_node {
            let mru_order: Vec<u32> = (|| -> Option<Vec<u32>> {
                let vi = rd_node.values()?.ok()?;
                for vr in vi { let v = match vr { Ok(v) => v, Err(_) => continue }; let n = match v.name() { Ok(n) => n.to_string_lossy(), Err(_) => continue }; if n.eq_ignore_ascii_case("MRUListEx") { let vd: Vec<u8> = match v.data() { Ok(d) => match d.into_vec() { Ok(v) => v, Err(_) => continue }, Err(_) => continue }; let mut o = Vec::new(); for ch in vd.chunks_exact(4) { if let Ok(arr) = <[u8;4]>::try_from(ch) { let idx = u32::from_le_bytes(arr); if idx == 0xFFFFFFFF { break; } o.push(idx); } } return Some(o); } }
                None
            })().unwrap_or_default();
            let mut mru_pos = std::collections::HashMap::new();
            for (p, &i) in mru_order.iter().enumerate() { mru_pos.insert(i, p); }
            if let Some(Ok(vi)) = rd_node.values() {
                for vr in vi {
                    let v = match vr { Ok(v) => v, Err(_) => continue };
                    let vn = match v.name() { Ok(n) => n.to_string_lossy(), Err(_) => continue };
                    let vidx: u32 = match vn.parse() { Ok(n) => n, Err(_) => continue };
                    let vd: Vec<u8> = match v.data() { Ok(d) => match d.into_vec() { Ok(v) => v, Err(_) => continue }, Err(_) => continue };
                    let filename = extract_utf16le_string(&vd);
                    if filename.is_empty() { continue; }
                    let mp = mru_pos.get(&vidx).copied().unwrap_or(usize::MAX);
                    let pd = if mp == usize::MAX { "unknown".to_string() } else { mp.to_string() };
                    let mut a = Artifact::new("Recent Document", &path_str); a.add_field("title", &filename); a.add_field("detail", &format!("MRU position: {} (0 = most recent)", pd)); a.add_field("file_type", "Recent Document"); a.add_field("forensic_value", "High"); artifacts.push(a);
                }
            }
        }

        // ── v0.7.0: ComDlg32 MRUs ─────────────────────────────────────
        // Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\
        //   OpenSavePidlMRU       — files opened/saved via standard dialog
        //   LastVisitedPidlMRU    — application + last directory pairs
        // Software\Microsoft\Windows\CurrentVersion\Explorer\
        //   RunMRU                — commands typed into Run dialog
        let cdlg_node: Option<nt_hive::KeyNode<'_, &[u8]>> = (|| {
            root.subkey("Software")?.ok()?
                .subkey("Microsoft")?.ok()?
                .subkey("Windows")?.ok()?
                .subkey("CurrentVersion")?.ok()?
                .subkey("Explorer")?.ok()?
                .subkey("ComDlg32")?.ok()
        })();
        if let Some(cdlg) = cdlg_node {
            // OpenSavePidlMRU — extension-named subkeys, each containing
            // numbered values that are PIDL byte blobs. We extract any
            // printable filename strings we can.
            if let Some(Ok(open_save)) = cdlg.subkey("OpenSavePidlMRU") {
                if let Some(Ok(ext_iter)) = open_save.subkeys() {
                    for ext_res in ext_iter {
                        let Ok(ext_node) = ext_res else { continue };
                        let Ok(ext_name) = ext_node.name() else { continue };
                        let ext_name = ext_name.to_string_lossy();
                        if let Some(Ok(values)) = ext_node.values() {
                            for vr in values {
                                let Ok(v) = vr else { continue };
                                let Ok(vn) = v.name() else { continue };
                                let vn_s = vn.to_string_lossy();
                                if vn_s == "MRUListEx" {
                                    continue;
                                }
                                let vd: Vec<u8> = match v.data() {
                                    Ok(d) => match d.into_vec() {
                                        Ok(b) => b,
                                        Err(_) => continue,
                                    },
                                    Err(_) => continue,
                                };
                                // Heuristic: scrape printable filename
                                let scraped = scrape_pidl_strings(&vd);
                                for s in scraped {
                                    let mut a = Artifact::new("OpenSavePidlMRU", &path_str);
                                    a.add_field("title", &format!("Opened/saved (.{}): {}", ext_name, s));
                                    a.add_field(
                                        "detail",
                                        &format!("Standard file dialog history for extension .{}", ext_name),
                                    );
                                    a.add_field("file_type", "OpenSavePidlMRU");
                                    a.add_field("forensic_value", "High");
                                    a.add_field("mitre", "T1083");
                                    artifacts.push(a);
                                }
                            }
                        }
                    }
                }
            }

            // LastVisitedPidlMRU — application + directory pairs
            if let Some(Ok(lv)) = cdlg.subkey("LastVisitedPidlMRU") {
                if let Some(Ok(values)) = lv.values() {
                    for vr in values {
                        let Ok(v) = vr else { continue };
                        let Ok(vn) = v.name() else { continue };
                        let vn_s = vn.to_string_lossy();
                        if vn_s == "MRUListEx" {
                            continue;
                        }
                        let vd: Vec<u8> = match v.data() {
                            Ok(d) => match d.into_vec() {
                                Ok(b) => b,
                                Err(_) => continue,
                            },
                            Err(_) => continue,
                        };
                        // First element is the executable name (UTF-16LE);
                        // remainder is the PIDL.
                        let exe_name = extract_utf16le_string(&vd);
                        if !exe_name.is_empty() {
                            let mut a = Artifact::new("LastVisitedPidlMRU", &path_str);
                            a.add_field("title", &format!("App used file dialog: {}", exe_name));
                            a.add_field(
                                "detail",
                                "Proves the application was executed AND used the standard file dialog",
                            );
                            a.add_field("file_type", "LastVisitedPidlMRU");
                            a.add_field("forensic_value", "High");
                            a.add_field("mitre", "T1204");
                            artifacts.push(a);
                        }
                    }
                }
            }
        }

        // RunMRU — direct user-typed commands in the Run dialog
        let run_mru_node: Option<nt_hive::KeyNode<'_, &[u8]>> = (|| {
            root.subkey("Software")?.ok()?
                .subkey("Microsoft")?.ok()?
                .subkey("Windows")?.ok()?
                .subkey("CurrentVersion")?.ok()?
                .subkey("Explorer")?.ok()?
                .subkey("RunMRU")?.ok()
        })();
        if let Some(rm) = run_mru_node {
            if let Some(Ok(values)) = rm.values() {
                for vr in values {
                    let Ok(v) = vr else { continue };
                    let Ok(vn) = v.name() else { continue };
                    let vn_s = vn.to_string_lossy();
                    if vn_s == "MRUList" || vn_s == "MRUListEx" {
                        continue;
                    }
                    let vd: Vec<u8> = match v.data() {
                        Ok(d) => match d.into_vec() {
                            Ok(b) => b,
                            Err(_) => continue,
                        },
                        Err(_) => continue,
                    };
                    let mut command = extract_utf16le_string(&vd);
                    // RunMRU entries have a trailing "\1" suffix — strip it.
                    if let Some(pos) = command.find('\u{1}') {
                        command.truncate(pos);
                    }
                    if command.is_empty() {
                        continue;
                    }
                    let suspicious = {
                        let lc = command.to_lowercase();
                        lc.contains("powershell")
                            || lc.contains("cmd ")
                            || lc.contains("wscript")
                            || lc.contains("\\temp\\")
                    };
                    let mut a = Artifact::new("RunMRU", &path_str);
                    a.add_field("title", &format!("User typed: {}", command));
                    a.add_field(
                        "detail",
                        "Direct user input via Run dialog (Win+R) — strong evidence of interactive execution",
                    );
                    a.add_field("file_type", "RunMRU");
                    a.add_field("forensic_value", if suspicious { "Critical" } else { "High" });
                    if suspicious {
                        a.add_field("suspicious", "true");
                    }
                    a.add_field("mitre", "T1059.003");
                    artifacts.push(a);
                }
            }
        }

        // ── v1.1.0: Office Recent Files (per app) ─────────────────────
        // Software\Microsoft\Office\<version>\<app>\File MRU
        // <version> = 14.0 / 15.0 / 16.0
        // <app>     = Word / Excel / PowerPoint / Access / Outlook / OneNote
        let office_versions = ["16.0", "15.0", "14.0"];
        let office_apps = ["Word", "Excel", "PowerPoint", "Access", "Outlook", "OneNote"];
        for ver in &office_versions {
            for app in &office_apps {
                let file_mru: Option<nt_hive::KeyNode<'_, &[u8]>> = (|| {
                    root.subkey("Software")?.ok()?
                        .subkey("Microsoft")?.ok()?
                        .subkey("Office")?.ok()?
                        .subkey(ver)?.ok()?
                        .subkey(app)?.ok()?
                        .subkey("File MRU")?.ok()
                })();
                if let Some(mru) = file_mru {
                    if let Some(Ok(values)) = mru.values() {
                        for vr in values {
                            let Ok(v) = vr else { continue };
                            let Ok(vname) = v.name() else { continue };
                            let vname_s = vname.to_string_lossy();
                            if vname_s == "Max Display" { continue; }
                            let vd: Vec<u8> = match v.data() {
                                Ok(d) => match d.into_vec() { Ok(b) => b, Err(_) => continue },
                                Err(_) => continue,
                            };
                            let raw = extract_utf16le_string(&vd);
                            // Office MRU values look like:
                            // [F00000000][T01D...]*\\path\to\file.docx
                            // Strip leading [...] tokens to get the path.
                            let cleaned = strip_office_mru_prefix(&raw);
                            if cleaned.is_empty() { continue; }
                            let lc = cleaned.to_lowercase();
                            let suspicious = lc.starts_with("\\\\")
                                || lc.contains("\\temp\\")
                                || lc.contains("\\appdata\\local\\temp")
                                || lc.starts_with("d:\\")
                                || lc.starts_with("e:\\");
                            let mut a = Artifact::new("Office Recent File", &path_str);
                            a.add_field("title", &format!("Office {}: {}", app, cleaned));
                            a.add_field(
                                "detail",
                                &format!("Office version {} {} File MRU", ver, app),
                            );
                            a.add_field("file_type", "Office Recent File");
                            a.add_field("mitre", "T1083");
                            if suspicious {
                                a.add_field("forensic_value", "High");
                                a.add_field("suspicious", "true");
                            } else {
                                a.add_field("forensic_value", "Medium");
                            }
                            artifacts.push(a);
                        }
                    }
                }

                // ── Office Trust Records ───────────────────────────────
                // Software\Microsoft\Office\<ver>\<app>\Security\
                //   Trusted Documents\TrustRecords
                let trust: Option<nt_hive::KeyNode<'_, &[u8]>> = (|| {
                    root.subkey("Software")?.ok()?
                        .subkey("Microsoft")?.ok()?
                        .subkey("Office")?.ok()?
                        .subkey(ver)?.ok()?
                        .subkey(app)?.ok()?
                        .subkey("Security")?.ok()?
                        .subkey("Trusted Documents")?.ok()?
                        .subkey("TrustRecords")?.ok()
                })();
                if let Some(tr) = trust {
                    if let Some(Ok(values)) = tr.values() {
                        for vr in values {
                            let Ok(v) = vr else { continue };
                            let Ok(vname) = v.name() else { continue };
                            let doc_path = vname.to_string_lossy();
                            // The value data is a 28-byte blob. Last 4 bytes
                            // are flags: 0x7FFFFFFF = full trust (macros
                            // enabled).
                            let vd: Vec<u8> = match v.data() {
                                Ok(d) => match d.into_vec() { Ok(b) => b, Err(_) => continue },
                                Err(_) => continue,
                            };
                            let macros_enabled = vd
                                .get(vd.len().saturating_sub(4)..)
                                .and_then(|b| b.try_into().ok().map(u32::from_le_bytes))
                                .map(|f| f == 0x7FFF_FFFF || f & 0x7FFF_FFFF == 0x7FFF_FFFF)
                                .unwrap_or(false);
                            // First 8 bytes are a FILETIME for when trust was granted
                            let ft = if vd.len() >= 8 {
                                i64::from_le_bytes(vd[0..8].try_into().unwrap_or([0; 8]))
                            } else {
                                0
                            };
                            let unix = filetime_to_unix(ft);
                            let mut a = Artifact::new("Office Trust Record", &path_str);
                            if let Some(u) = unix {
                                a.timestamp = Some(u as u64);
                            }
                            a.add_field(
                                "title",
                                &format!("Office Trust ({}): {}", app, doc_path),
                            );
                            a.add_field(
                                "detail",
                                &format!(
                                    "User {} on {} | doc: {}",
                                    if macros_enabled {
                                        "ENABLED MACROS"
                                    } else {
                                        "trusted editing"
                                    },
                                    unix.map(|u| {
                                        chrono::DateTime::from_timestamp(u, 0)
                                            .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                                            .unwrap_or_else(|| format!("unix:{}", u))
                                    })
                                    .unwrap_or_else(|| "unknown date".to_string()),
                                    doc_path
                                ),
                            );
                            a.add_field("file_type", "Office Trust Record");
                            a.add_field("mitre", "T1566.001");
                            a.add_field("forensic_value", if macros_enabled { "Critical" } else { "High" });
                            a.add_field("suspicious", "true");
                            artifacts.push(a);
                        }
                    }
                }
            }
        }

        artifacts
    }

    /// Strip Office MRU `[F.....][T....]*` token prefixes to get the bare path.
    /// Used by parse_ntuser_dat for Office File MRU entries.
    #[allow(dead_code)]
    fn _strip_office_mru_dummy() {}

    /// GAP 2: Parse Jump List CFB/OLE2 compound file.
    fn parse_jumplist_cfb(path: &Path, data: &[u8], app_name: &str) -> Vec<Artifact> {
        let mut artifacts = Vec::new();
        let path_str = path.to_string_lossy().to_string();
        let mut compound = match cfb::CompoundFile::open(std::io::Cursor::new(data)) { Ok(c) => c, Err(_) => return artifacts };
        let entries: Vec<(String, bool)> = compound.walk().map(|e| (e.name().to_string(), e.is_stream())).collect();
        for (en, is) in &entries {
            if !is { continue; }
            if en == "DestList" {
                if let Ok(mut s) = compound.open_stream(en) { let mut buf = Vec::new(); if std::io::Read::read_to_end(&mut s, &mut buf).is_ok() { let mut a = Artifact::new("Jump List Entry", &path_str); a.add_field("title", &format!("JumpList DestList: {}", app_name)); a.add_field("detail", &format!("App: {} | DestList found with {} bytes", app_name, buf.len())); a.add_field("file_type", "Jump List Entry"); a.add_field("forensic_value", "High"); artifacts.push(a); } }
                continue;
            }
            if en.chars().all(|c| c.is_ascii_hexdigit()) || en.parse::<u64>().is_ok() {
                if let Ok(mut s) = compound.open_stream(en) {
                    let mut buf = Vec::new();
                    if std::io::Read::read_to_end(&mut s, &mut buf).is_ok() && buf.len() >= 0x4C && buf[0..4] == [0x4C,0x00,0x00,0x00] {
                        let mf = if buf.len() >= 0x2C { i64::from_le_bytes(buf[0x24..0x2C].try_into().unwrap_or([0;8])) } else { 0 };
                        let mu = filetime_to_unix(mf);
                        let target = extract_lnk_target(&buf);
                        let tf = if !target.is_empty() { Path::new(&target).file_name().and_then(|n| n.to_str()).unwrap_or(&target).to_string() } else { format!("Stream {}", en) };
                        let ts = mu.map(|t| chrono::DateTime::from_timestamp(t, 0).map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string()).unwrap_or_else(|| format!("unix:{}", t))).unwrap_or_else(|| "N/A".to_string());
                        let mut a = Artifact::new("Jump List Entry", &path_str); a.timestamp = mu.map(|t| t as u64); a.add_field("title", &format!("JumpList: {}", tf)); a.add_field("detail", &format!("App: {} | Stream: {} | Target: {} | Modified: {}", app_name, en, if target.is_empty() { "(unresolved)" } else { &target }, ts)); a.add_field("file_type", "Jump List Entry"); a.add_field("forensic_value", "High"); a.add_field("mitre", "T1547.009"); artifacts.push(a);
                    }
                }
            }
        }
        artifacts
    }
}

fn extract_utf16le_string(data: &[u8]) -> String {
    let u16s: Vec<u16> = data.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&ch| ch != 0).collect();
    String::from_utf16_lossy(&u16s)
}

/// Strip Office MRU `[F.....][T....]*` prefix tokens to recover the bare
/// path. Office stores File MRU entries as
/// `[F00000000][T01D5...]*\\server\\share\\file.docx`.
fn strip_office_mru_prefix(raw: &str) -> String {
    let mut s = raw.trim().to_string();
    while s.starts_with('[') {
        if let Some(end) = s.find(']') {
            s = s[end + 1..].to_string();
        } else {
            break;
        }
    }
    if let Some(stripped) = s.strip_prefix('*') {
        s = stripped.to_string();
    }
    s.trim().to_string()
}

/// Scrape printable filename-like strings from a binary PIDL blob. PIDLs are
/// nested ITEMIDLIST structures and full decoding is involved; this heuristic
/// finds embedded UTF-16LE display names that PIDLs almost always carry. Used
/// by the OpenSavePidlMRU parser.
fn scrape_pidl_strings(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 8 <= data.len() {
        let chunk_end = (i + 512).min(data.len());
        let chunk = &data[i..chunk_end];
        let mut s = String::new();
        let mut j = 0;
        while j + 2 <= chunk.len() {
            let c = u16::from_le_bytes([chunk[j], chunk[j + 1]]);
            if c == 0 { break; }
            if let Some(ch) = char::from_u32(c as u32) {
                if ch.is_ascii_graphic() || ch == ' ' { s.push(ch); } else { break; }
            } else { break; }
            j += 2;
        }
        if s.len() >= 4 && (s.contains('.') || s.contains('\\')) {
            out.push(s.clone());
        }
        i += s.len().max(2) * 2 + 2;
        if out.len() > 50 { break; }
    }
    out
}
fn extract_lnk_target(data: &[u8]) -> String {
    if data.len() < 0x4C { return String::new(); }
    let flags = u32::from_le_bytes(data[0x14..0x18].try_into().unwrap_or([0;4]));
    let hid = flags & 0x01 != 0; let hli = flags & 0x02 != 0;
    let mut off = 0x4C_usize;
    if hid { if data.len() >= off+2 { off += 2 + u16::from_le_bytes(data[off..off+2].try_into().unwrap_or([0;2])) as usize; } else { return String::new(); } }
    if hli && off+4 <= data.len() { let lis = u32::from_le_bytes(data[off..off+4].try_into().unwrap_or([0;4])) as usize; if lis >= 28 && off+lis <= data.len() { let li = &data[off..off+lis]; if li.len() >= 20 { let lbo = u32::from_le_bytes(li[16..20].try_into().unwrap_or([0;4])) as usize; if lbo > 0 && lbo < li.len() { let pb = &li[lbo..]; if let Some(end) = pb.iter().position(|&b| b==0) { return String::from_utf8_lossy(&pb[..end]).to_string(); } } } } }
    String::new()
}
fn filetime_to_unix(ft: i64) -> Option<i64> { if ft <= 0 { return None; } let u = (ft - 116444736000000000) / 10000000; if u < 0 { None } else { Some(u) } }
fn table_exists(conn: &rusqlite::Connection, tn: &str) -> bool { conn.prepare(&format!("SELECT 1 FROM sqlite_master WHERE type='table' AND name='{}'", tn)).and_then(|mut s| s.query_row([], |_| Ok(()))).is_ok() }

impl StrataPlugin for ChroniclePlugin {
    fn name(&self) -> &str { &self.name }
    fn version(&self) -> &str { &self.version }
    fn supported_inputs(&self) -> Vec<String> { vec!["artifacts".to_string()] }
    fn plugin_type(&self) -> PluginType { PluginType::Analyzer }
    fn capabilities(&self) -> Vec<PluginCapability> { vec![PluginCapability::TimelineEnrichment, PluginCapability::ArtifactExtraction] }
    fn description(&self) -> &str { "Timeline enrichment from all artifact sources" }
    fn run(&self, ctx: PluginContext) -> PluginResult {
        let root = Path::new(&ctx.root_path);
        let mut results = Vec::new();
        if let Ok(entries) = walk_dir(root) {
            for entry_path in entries {
                if let Some((ft, _)) = Self::classify_file(&entry_path) {
                    let ps = entry_path.to_string_lossy().to_string();
                    let sp = Self::is_suspicious_path(&entry_path);
                    match ft {
                        "Prefetch" => { if let Ok(data) = std::fs::read(&entry_path) { let parsed = Self::parse_prefetch_content(&entry_path, &data); if parsed.is_empty() { let mut a = Artifact::new("Prefetch Executions", &ps); a.add_field("title", &format!("Prefetch: {}", ps)); a.add_field("detail", "Prefetch file (unparseable)"); a.add_field("file_type", "Prefetch"); a.add_field("suspicious", if sp {"true"} else {"false"}); results.push(a); } else { for (t,d,ts) in parsed { let mut a = Artifact::new("Prefetch Executions", &ps); a.timestamp = ts.map(|t| t as u64); a.add_field("title", &t); a.add_field("detail", &d); a.add_field("file_type", "Prefetch"); a.add_field("suspicious", if sp {"true"} else {"false"}); results.push(a); } } } }
                        "Browser History" => { let parsed = Self::parse_browser_history_sqlite(&entry_path); if parsed.is_empty() { let mut a = Artifact::new("Browser History", &ps); a.add_field("title", "Browser history (empty or locked)"); a.add_field("detail", &format!("File: {}", ps)); a.add_field("file_type", "Browser History"); a.add_field("suspicious", if sp {"true"} else {"false"}); results.push(a); } else { for (t,d,ts) in parsed { let is_sus = d.contains("[SUSPICIOUS]") || sp; let mut a = Artifact::new("Browser History", &ps); a.timestamp = ts.map(|t| t as u64); a.add_field("title", &t); a.add_field("detail", &d); a.add_field("file_type", "Browser History"); a.add_field("suspicious", if is_sus {"true"} else {"false"}); results.push(a); } } }
                        "LNK Shortcut" => { if let Ok(data) = std::fs::read(&entry_path) { let parsed = Self::parse_lnk_content(&entry_path, &data); if parsed.is_empty() { let mut a = Artifact::new("Recent Files", &ps); a.add_field("title", &format!("LNK: {}", ps)); a.add_field("detail", "LNK file (unparseable)"); a.add_field("file_type", "LNK Shortcut"); a.add_field("suspicious", if sp {"true"} else {"false"}); results.push(a); } else { for (t,d,ts) in parsed { let mut a = Artifact::new("Recent Files", &ps); a.timestamp = ts.map(|t| t as u64); a.add_field("title", &t); a.add_field("detail", &d); a.add_field("file_type", "LNK Shortcut"); a.add_field("suspicious", if sp {"true"} else {"false"}); results.push(a); } } } }
                        "Windows Event Log" => { let mut a = Artifact::new("Event Logs", &ps); a.add_field("title", &format!("Event Log: {}", entry_path.file_name().and_then(|n| n.to_str()).unwrap_or("unknown"))); a.add_field("detail", &format!("EVTX file noted (deep parse pending): {}", ps)); a.add_field("file_type", "Windows Event Log"); a.add_field("suspicious", if sp {"true"} else {"false"}); results.push(a); }
                        _ => {}
                    }
                }
                let ps = entry_path.to_string_lossy().to_string();
                let fn_ = entry_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                results.extend(Self::detect_recent_docs(&ps, fn_));
                results.extend(Self::detect_typed_paths(&ps, fn_));
                results.extend(Self::detect_word_wheel_query(&ps, fn_));
                results.extend(Self::detect_activities_cache(&ps, fn_));
                results.extend(Self::detect_capability_access(&ps, fn_));
                results.extend(Self::detect_userassist(&entry_path, fn_, &ps));
                results.extend(Self::detect_recentdocs_detailed(&entry_path, fn_, &ps));
                results.extend(Self::detect_jumplist(&entry_path, fn_, &ps));
                if fn_.eq_ignore_ascii_case("NTUSER.DAT") { if let Ok(data) = std::fs::read(&entry_path) { results.extend(Self::parse_ntuser_dat(&entry_path, &data)); } }

                // ── v1.1.0: Browser Media History (Chrome / Edge) ────
                if fn_.eq_ignore_ascii_case("Media History") {
                    let parsed = Self::parse_media_history(&entry_path);
                    if parsed.is_empty() {
                        let mut a = Artifact::new("Media History", &ps);
                        a.add_field("title", "Browser Media History present");
                        a.add_field(
                            "detail",
                            "Chrome/Edge Media History DB found — 'playbackSession' table not parseable or empty",
                        );
                        a.add_field("file_type", "Media History");
                        a.add_field("forensic_value", "Low");
                        results.push(a);
                    } else {
                        for art in parsed {
                            results.push(art);
                        }
                    }
                }

                // ── v1.1.0: Browser Session restore files ────────────
                let lc_name = fn_.to_lowercase();
                if (lc_name.starts_with("session_") || lc_name.starts_with("tabs_"))
                    && (ps.to_lowercase().contains("\\sessions")
                        || ps.to_lowercase().contains("/sessions"))
                {
                    let mut a = Artifact::new("Browser Session", &ps);
                    a.add_field("title", &format!("Browser session file: {}", fn_));
                    a.add_field(
                        "detail",
                        "Chromium-based browser session/tab restore file. Contains tabs open at last browser close. Parse with specialized session-restore decoder for full reconstruction.",
                    );
                    a.add_field("file_type", "Browser Session");
                    a.add_field("forensic_value", "Medium");
                    results.push(a);
                }

                if fn_.to_lowercase().ends_with(".automaticdestinations-ms") {
                    if let Ok(data) = std::fs::read(&entry_path) {
                        let aid = fn_.split('.').next().unwrap_or("unknown");
                        let known: &[(&str,&str)] = &[("1b4dd67f29cb1962","Windows Explorer"),("5f7b5f1e01b83767","Internet Explorer"),("b91c07e03a5a0a35","Google Chrome"),("5d696d521de238c3","Google Chrome"),("9b9cdc69c1c24e2b","Mozilla Firefox"),("9c764ede09a2f88e","Microsoft Edge"),("a7bd71699cd38d1c","Microsoft Word"),("f0275e1002be10b2","Microsoft Excel"),("ee9f71d9828e153e","Microsoft Outlook"),("d00655d2aa12ff6d","Excel 2016+"),("b0459d4b0fb86a58","Notepad"),("2e61e3e1604d0de3","Paint"),("6ec72ce0fdc76d9e","Windows Media Player"),("3dc09a3a42e88c38","Adobe Reader"),("7494a606a9eef18e","Adobe Acrobat"),("64bc1e327c5f8b8a","7-Zip"),("a1c8b4d3e2f09175","VLC Media Player"),("f38b1c0d3e9a7625","Visual Studio Code"),("4975d6798a1a4326","VS Code"),("1bc392b8e104a00e","Remote Desktop"),("bcc705e07d55efb0","PuTTY")];
                        let rn = known.iter().find(|(id,_)| id.eq_ignore_ascii_case(aid)).map(|(_,n)| *n).unwrap_or(aid);
                        results.extend(Self::parse_jumplist_cfb(&entry_path, &data, rn));
                    }
                }
            }
        }
        Ok(results)
    }
    fn execute(&self, context: PluginContext) -> Result<PluginOutput, PluginError> {
        let start = std::time::Instant::now();
        let artifacts = self.run(context)?;
        let mut records = Vec::new();
        let mut sources = HashSet::new();
        for artifact in &artifacts {
            let file_type = artifact.data.get("file_type").cloned().unwrap_or_default();
            let ps = artifact.source.clone();
            let p = Path::new(&ps);
            let sf = artifact.data.get("suspicious").map(|s| s == "true").unwrap_or(false);
            let suspicious = sf || Self::is_suspicious_path(p);
            sources.insert(file_type.clone());
            let category = match file_type.as_str() { "Prefetch" | "UserAssist Execution" => ArtifactCategory::ExecutionHistory, "Windows Event Log" => ArtifactCategory::SystemActivity, "Browser History" => ArtifactCategory::WebActivity, _ => ArtifactCategory::UserActivity };
            let subcategory = artifact.category.clone();
            let ef = artifact.data.get("forensic_value").cloned().unwrap_or_default();
            let fv = if ef == "Critical" { ForensicValue::Critical } else if suspicious || ef == "High" { ForensicValue::High } else { ForensicValue::Medium };
            let mt = artifact.data.get("mitre").cloned();
            records.push(ArtifactRecord { category, subcategory, timestamp: artifact.timestamp.map(|t| t as i64), title: artifact.data.get("title").cloned().unwrap_or_else(|| artifact.source.clone()), detail: artifact.data.get("detail").cloned().unwrap_or_default(), source_path: artifact.source.clone(), forensic_value: fv, mitre_technique: mt, is_suspicious: suspicious, raw_data: None });
        }
        let sc = records.iter().filter(|r| r.is_suspicious).count();
        let cats: Vec<String> = records.iter().map(|r| r.category.as_str().to_string()).collect::<HashSet<_>>().into_iter().collect();
        Ok(PluginOutput { plugin_name: self.name().to_string(), plugin_version: self.version().to_string(), executed_at: String::new(), duration_ms: start.elapsed().as_millis() as u64, artifacts: records.clone(), summary: PluginSummary { total_artifacts: records.len(), suspicious_count: sc, categories_populated: cats, headline: format!("Built timeline: {} events from {} sources, {} suspicious", records.len(), sources.len(), sc) }, warnings: vec![] })
    }
}

use strata_plugin_sdk::PluginError;

fn walk_dir(dir: &Path) -> Result<Vec<PathBuf>, std::io::Error> {
    let mut paths = Vec::new();
    if dir.is_dir() { for entry in std::fs::read_dir(dir)? { let entry = entry?; let path = entry.path(); if path.is_dir() { if let Ok(sub) = walk_dir(&path) { paths.extend(sub); } } else { paths.push(path); } } }
    Ok(paths)
}

#[no_mangle]
pub extern "C" fn create_plugin_chronicle() -> *mut std::ffi::c_void {
    let plugin: Box<dyn StrataPlugin> = Box::new(ChroniclePlugin::new());
    Box::into_raw(Box::new(plugin)) as *mut std::ffi::c_void
}
