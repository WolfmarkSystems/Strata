use serde_json::json;

#[tauri::command]
fn get_app_version() -> String {
    "0.3.0".to_string()
}

#[tauri::command]
fn check_license() -> serde_json::Value {
    json!({
        "status": "dev",
        "days": 999,
        "licensee": "Dev Mode",
        "tier": "pro"
    })
}

#[tauri::command]
fn get_examiner_profile() -> serde_json::Value {
    json!({
        "name": "Dev Examiner",
        "agency": "Wolfmark Systems",
        "badge": "DEV-001"
    })
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_app_version,
            check_license,
            get_examiner_profile,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
