//! RandoChat — random chat app message extraction.
//!
//! ALEAPP reference: `scripts/artifacts/RandoChat.py`. Source path:
//! `/data/data/com.random.chat.app/databases/ramdochatV2.db*`.
//!
//! Key tables: `mensagens` (messages), `conversa` (contacts),
//! `configuracao` (account settings) — all Portuguese names.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.random.chat.app/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "mensagens") {
        out.extend(read_messages(&conn, path));
    }
    if table_exists(&conn, "conversa") {
        out.extend(read_contacts(&conn, path));
    }
    if table_exists(&conn, "configuracao") {
        out.extend(read_config(&conn, path));
    }
    out
}

fn read_messages(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT timestamp, conteudo, username, enviada, \
               arquivo, conversa_id, mensagem_id \
               FROM mensagens \
               ORDER BY timestamp DESC LIMIT 10000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<String>>(5).unwrap_or(None),
            row.get::<_, Option<String>>(6).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (ts_ms, content, username, sent, file, conv_id, msg_id) in rows.flatten() {
        let username = username.unwrap_or_else(|| "(unknown)".to_string());
        let body = content.unwrap_or_default();
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let direction = if sent.unwrap_or(0) != 0 {
            "sent"
        } else {
            "received"
        };
        let conv_id = conv_id.unwrap_or_default();
        let msg_id = msg_id.unwrap_or_default();
        let file = file.unwrap_or_default();
        let preview: String = body.chars().take(120).collect();
        let title = format!("RandoChat {} {}: {}", direction, username, preview);
        let mut detail = format!(
            "RandoChat message direction={} username='{}' conv_id='{}' body='{}'",
            direction, username, conv_id, body
        );
        if !file.is_empty() {
            detail.push_str(&format!(" file='{}'", file));
        }
        if !msg_id.is_empty() {
            detail.push_str(&format!(" msg_id='{}'", msg_id));
        }
        out.push(build_record(
            ArtifactCategory::SocialMedia,
            "RandoChat Message",
            title,
            detail,
            path,
            ts,
            ForensicValue::High,
            false,
        ));
    }
    out
}

fn read_contacts(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT account_id, username, age, sex, favorito, bloqueado \
               FROM conversa LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<i64>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (account_id, username, age, sex, favorite, blocked) in rows.flatten() {
        let account_id = account_id.unwrap_or_else(|| "(unknown)".to_string());
        let username = username.unwrap_or_else(|| "(no name)".to_string());
        let is_fav = favorite.unwrap_or(0) != 0;
        let is_blocked = blocked.unwrap_or(0) != 0;
        let title = format!("RandoChat contact: {} ({})", username, account_id);
        let mut detail = format!(
            "RandoChat contact account_id='{}' username='{}' favorite={} blocked={}",
            account_id, username, is_fav, is_blocked
        );
        if let Some(a) = age {
            detail.push_str(&format!(" age={}", a));
        }
        if let Some(s) = sex.filter(|s| !s.is_empty()) {
            detail.push_str(&format!(" sex='{}'", s));
        }
        out.push(build_record(
            ArtifactCategory::SocialMedia,
            "RandoChat Contact",
            title,
            detail,
            path,
            None,
            ForensicValue::Medium,
            false,
        ));
    }
    out
}

fn read_config(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT username, sex, age, idioma, device_id, \
               preferidade_de, preferidade_ate, preferido_sex \
               FROM configuracao LIMIT 10";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<String>>(1).unwrap_or(None),
            row.get::<_, Option<i64>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<String>>(4).unwrap_or(None),
            row.get::<_, Option<i64>>(5).unwrap_or(None),
            row.get::<_, Option<i64>>(6).unwrap_or(None),
            row.get::<_, Option<String>>(7).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (username, sex, age, lang, device, age_from, age_to, pref_sex) in rows.flatten() {
        let username = username.unwrap_or_else(|| "(unknown)".to_string());
        let device = device.unwrap_or_default();
        let title = format!("RandoChat account: {}", username);
        let mut detail = format!("RandoChat account username='{}'", username);
        if let Some(s) = sex.filter(|s| !s.is_empty()) {
            detail.push_str(&format!(" sex='{}'", s));
        }
        if let Some(a) = age {
            detail.push_str(&format!(" age={}", a));
        }
        if let Some(l) = lang.filter(|l| !l.is_empty()) {
            detail.push_str(&format!(" language='{}'", l));
        }
        if !device.is_empty() {
            detail.push_str(&format!(" device_id='{}'", device));
        }
        if let (Some(f), Some(t)) = (age_from, age_to) {
            detail.push_str(&format!(" preferred_age={}-{}", f, t));
        }
        if let Some(p) = pref_sex.filter(|p| !p.is_empty()) {
            detail.push_str(&format!(" preferred_sex='{}'", p));
        }
        out.push(build_record(
            ArtifactCategory::AccountsCredentials,
            "RandoChat Account",
            title,
            detail,
            path,
            None,
            ForensicValue::High,
            false,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn make_db() -> tempfile::NamedTempFile {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch(
            r#"
            CREATE TABLE mensagens (
                timestamp INTEGER,
                conteudo TEXT,
                username TEXT,
                enviada INTEGER,
                arquivo TEXT,
                conversa_id TEXT,
                mensagem_id TEXT
            );
            INSERT INTO mensagens VALUES(1609459200000,'Hello!','user_x',1,NULL,'c1','m1');
            INSERT INTO mensagens VALUES(1609459300000,'Hi back','user_x',0,NULL,'c1','m2');
            CREATE TABLE conversa (
                account_id TEXT,
                username TEXT,
                age INTEGER,
                sex TEXT,
                favorito INTEGER,
                bloqueado INTEGER,
                link_profile_pic TEXT
            );
            INSERT INTO conversa VALUES('acc_1','user_x',25,'F',1,0,NULL);
            CREATE TABLE configuracao (
                username TEXT,
                sex TEXT,
                age INTEGER,
                idioma TEXT,
                device_id TEXT,
                preferidade_de INTEGER,
                preferidade_ate INTEGER,
                preferido_sex TEXT
            );
            INSERT INTO configuracao VALUES('myname','M',30,'en','device_abc123',25,35,'F');
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_all_three_tables() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "RandoChat Message"));
        assert!(r.iter().any(|a| a.subcategory == "RandoChat Contact"));
        assert!(r.iter().any(|a| a.subcategory == "RandoChat Account"));
    }

    #[test]
    fn account_device_id_captured() {
        let db = make_db();
        let r = parse(db.path());
        let acc = r
            .iter()
            .find(|a| a.subcategory == "RandoChat Account")
            .unwrap();
        assert!(acc.detail.contains("device_id='device_abc123'"));
        assert!(acc.detail.contains("preferred_age=25-35"));
    }

    #[test]
    fn contact_favorite_flag() {
        let db = make_db();
        let r = parse(db.path());
        let contact = r
            .iter()
            .find(|a| a.subcategory == "RandoChat Contact")
            .unwrap();
        assert!(contact.detail.contains("favorite=true"));
    }

    #[test]
    fn missing_table_yields_empty() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let c = Connection::open(tmp.path()).unwrap();
        c.execute_batch("CREATE TABLE unrelated (id INTEGER);")
            .unwrap();
        drop(c);
        assert!(parse(tmp.path()).is_empty());
    }
}
