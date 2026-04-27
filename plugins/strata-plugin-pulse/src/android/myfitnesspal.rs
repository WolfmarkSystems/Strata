//! MyFitnessPal — food diary and weight tracking.
//!
//! Source path: `/data/data/com.myfitnesspal.android/databases/*.db`.
//!
//! Schema note: not in ALEAPP upstream. MFP caches diary entries, food
//! database items, weight measurements, and exercise log.

use crate::android::helpers::{build_record, open_sqlite_ro, table_exists, unix_ms_to_i64};
use std::path::Path;
use strata_plugin_sdk::{ArtifactCategory, ArtifactRecord, ForensicValue};

pub const MATCHES: &[&str] = &["com.myfitnesspal.android/databases/"];

pub fn parse(path: &Path) -> Vec<ArtifactRecord> {
    let Some(conn) = open_sqlite_ro(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if table_exists(&conn, "diary_entry") {
        out.extend(read_diary(&conn, path));
    }
    if table_exists(&conn, "weight_entry") {
        out.extend(read_weight(&conn, path));
    }
    if table_exists(&conn, "exercise_entry") {
        out.extend(read_exercise(&conn, path));
    }
    out
}

fn read_diary(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT id, date, meal, food_name, servings, calories, \
               carbs_g, protein_g, fat_g \
               FROM diary_entry ORDER BY date DESC LIMIT 10000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<String>>(3).unwrap_or(None),
            row.get::<_, Option<f64>>(4).unwrap_or(None),
            row.get::<_, Option<f64>>(5).unwrap_or(None),
            row.get::<_, Option<f64>>(6).unwrap_or(None),
            row.get::<_, Option<f64>>(7).unwrap_or(None),
            row.get::<_, Option<f64>>(8).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, ts_ms, meal, food_name, servings, calories, carbs, protein, fat) in rows.flatten() {
        let id = id.unwrap_or_default();
        let meal = meal.unwrap_or_default();
        let food_name = food_name.unwrap_or_else(|| "(unknown)".to_string());
        let servings = servings.unwrap_or(0.0);
        let calories = calories.unwrap_or(0.0);
        let carbs = carbs.unwrap_or(0.0);
        let protein = protein.unwrap_or(0.0);
        let fat = fat.unwrap_or(0.0);
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("MFP {}: {} ({:.0} cal)", meal, food_name, calories);
        let detail = format!(
            "MyFitnessPal diary id='{}' meal='{}' food_name='{}' servings={:.2} calories={:.0} carbs_g={:.1} protein_g={:.1} fat_g={:.1}",
            id, meal, food_name, servings, calories, carbs, protein, fat
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "MyFitnessPal Diary",
            title,
            detail,
            path,
            ts,
            ForensicValue::Low,
            false,
        ));
    }
    out
}

fn read_weight(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT date, weight_kg FROM weight_entry \
               ORDER BY date DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<i64>>(0).unwrap_or(None),
            row.get::<_, Option<f64>>(1).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (ts_ms, weight_kg) in rows.flatten() {
        let weight_kg = weight_kg.unwrap_or(0.0);
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("MFP weight: {:.1} kg", weight_kg);
        let detail = format!("MyFitnessPal weight entry weight_kg={:.2}", weight_kg);
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "MyFitnessPal Weight",
            title,
            detail,
            path,
            ts,
            ForensicValue::Low,
            false,
        ));
    }
    out
}

fn read_exercise(conn: &rusqlite::Connection, path: &Path) -> Vec<ArtifactRecord> {
    let sql = "SELECT id, date, exercise_name, duration_minutes, calories_burned \
               FROM exercise_entry ORDER BY date DESC LIMIT 5000";
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0).unwrap_or(None),
            row.get::<_, Option<i64>>(1).unwrap_or(None),
            row.get::<_, Option<String>>(2).unwrap_or(None),
            row.get::<_, Option<i64>>(3).unwrap_or(None),
            row.get::<_, Option<f64>>(4).unwrap_or(None),
        ))
    });
    let Ok(rows) = rows else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (id, ts_ms, exercise_name, duration, calories) in rows.flatten() {
        let id = id.unwrap_or_default();
        let exercise_name = exercise_name.unwrap_or_else(|| "(unknown)".to_string());
        let duration = duration.unwrap_or(0);
        let calories = calories.unwrap_or(0.0);
        let ts = ts_ms.and_then(unix_ms_to_i64);
        let title = format!("MFP exercise: {} ({} min)", exercise_name, duration);
        let detail = format!(
            "MyFitnessPal exercise id='{}' exercise_name='{}' duration_minutes={} calories_burned={:.0}",
            id, exercise_name, duration, calories
        );
        out.push(build_record(
            ArtifactCategory::UserActivity,
            "MyFitnessPal Exercise",
            title,
            detail,
            path,
            ts,
            ForensicValue::Low,
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
            CREATE TABLE diary_entry (
                id TEXT,
                date INTEGER,
                meal TEXT,
                food_name TEXT,
                servings REAL,
                calories REAL,
                carbs_g REAL,
                protein_g REAL,
                fat_g REAL
            );
            INSERT INTO diary_entry VALUES('d1',1609459200000,'breakfast','Oatmeal',1.0,150.0,27.0,5.0,3.0);
            CREATE TABLE weight_entry (
                date INTEGER,
                weight_kg REAL
            );
            INSERT INTO weight_entry VALUES(1609459200000,75.5);
            CREATE TABLE exercise_entry (
                id TEXT,
                date INTEGER,
                exercise_name TEXT,
                duration_minutes INTEGER,
                calories_burned REAL
            );
            INSERT INTO exercise_entry VALUES('ex1',1609459300000,'Running',30,300.0);
            "#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn parses_diary_weight_exercise() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r.iter().any(|a| a.subcategory == "MyFitnessPal Diary"));
        assert!(r.iter().any(|a| a.subcategory == "MyFitnessPal Weight"));
        assert!(r.iter().any(|a| a.subcategory == "MyFitnessPal Exercise"));
    }

    #[test]
    fn macro_values_captured() {
        let db = make_db();
        let r = parse(db.path());
        let d = r
            .iter()
            .find(|a| a.subcategory == "MyFitnessPal Diary")
            .unwrap();
        assert!(d.detail.contains("carbs_g=27.0"));
        assert!(d.detail.contains("protein_g=5.0"));
    }

    #[test]
    fn exercise_duration_in_title() {
        let db = make_db();
        let r = parse(db.path());
        assert!(r
            .iter()
            .any(|a| a.title.contains("Running") && a.title.contains("30 min")));
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
