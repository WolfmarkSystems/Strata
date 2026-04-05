use crate::errors::ForensicError;

pub fn create_csv_header(columns: &[&str]) -> String {
    columns.join(",")
}

pub fn create_csv_row(values: &[String]) -> String {
    values
        .iter()
        .map(|v| {
            if v.contains(',') || v.contains('"') || v.contains('\n') {
                format!("\"{}\"", v.replace('"', "\"\""))
            } else {
                v.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

pub fn export_timeline_csv(
    events: &[(u64, String, String, String)],
) -> Result<String, ForensicError> {
    let mut csv = String::new();
    csv.push_str("Timestamp,Source,EventType,Description\n");

    for (timestamp, source, event_type, description) in events {
        let row = create_csv_row(&[
            timestamp.to_string(),
            source.clone(),
            event_type.clone(),
            description.clone(),
        ]);
        csv.push_str(&row);
        csv.push('\n');
    }

    Ok(csv)
}

pub fn export_artifacts_csv(
    artifacts: &[(String, String, String, String, String)],
) -> Result<String, ForensicError> {
    let mut csv = String::new();
    csv.push_str("Name,Type,Path,Value,Timestamp\n");

    for (name, art_type, path, value, timestamp) in artifacts {
        let row = create_csv_row(&[
            name.clone(),
            art_type.clone(),
            path.clone(),
            value.clone(),
            timestamp.to_string(),
        ]);
        csv.push_str(&row);
        csv.push('\n');
    }

    Ok(csv)
}

pub fn export_files_csv(
    files: &[(String, String, u64, String, String, String)],
) -> Result<String, ForensicError> {
    let mut csv = String::new();
    csv.push_str("Name,Path,Size,Created,Modified,Accessed\n");

    for (name, path, size, created, modified, accessed) in files {
        let row = create_csv_row(&[
            name.clone(),
            path.clone(),
            size.to_string(),
            created.clone(),
            modified.clone(),
            accessed.clone(),
        ]);
        csv.push_str(&row);
        csv.push('\n');
    }

    Ok(csv)
}

pub fn export_registry_csv(
    entries: &[(String, String, String, String)],
) -> Result<String, ForensicError> {
    let mut csv = String::new();
    csv.push_str("Key,ValueName,ValueType,ValueData\n");

    for (key, value_name, value_type, value_data) in entries {
        let row = create_csv_row(&[
            key.clone(),
            value_name.clone(),
            value_type.clone(),
            value_data.clone(),
        ]);
        csv.push_str(&row);
        csv.push('\n');
    }

    Ok(csv)
}

pub fn export_hash_db_csv(
    entries: &[(String, String, String, String)],
) -> Result<String, ForensicError> {
    let mut csv = String::new();
    csv.push_str("Hash,Filename,Size,Source\n");

    for (hash, filename, size, source) in entries {
        let row = create_csv_row(&[
            hash.clone(),
            filename.clone(),
            size.to_string(),
            source.clone(),
        ]);
        csv.push_str(&row);
        csv.push('\n');
    }

    Ok(csv)
}

pub fn export_connections_csv(
    connections: &[(String, u16, String, u16, String, String)],
) -> Result<String, ForensicError> {
    let mut csv = String::new();
    csv.push_str("LocalAddress,LocalPort,RemoteAddress,RemotePort,State,Process\n");

    for (local_addr, local_port, remote_addr, remote_port, state, process) in connections {
        let row = create_csv_row(&[
            local_addr.clone(),
            local_port.to_string(),
            remote_addr.clone(),
            remote_port.to_string(),
            state.clone(),
            process.clone(),
        ]);
        csv.push_str(&row);
        csv.push('\n');
    }

    Ok(csv)
}

pub fn export_process_csv(
    processes: &[(u32, String, u32, String, String)],
) -> Result<String, ForensicError> {
    let mut csv = String::new();
    csv.push_str("PID,Name,PPID,CommandLine,User\n");

    for (pid, name, ppid, cmdline, user) in processes {
        let row = create_csv_row(&[
            pid.to_string(),
            name.clone(),
            ppid.to_string(),
            cmdline.clone(),
            user.clone(),
        ]);
        csv.push_str(&row);
        csv.push('\n');
    }

    Ok(csv)
}

pub fn export_findings_csv(
    findings: &[(String, String, String, String, String)],
) -> Result<String, ForensicError> {
    let mut csv = String::new();
    csv.push_str("Category,Severity,Title,Source,Description\n");

    for (category, severity, title, source, description) in findings {
        let row = create_csv_row(&[
            category.clone(),
            severity.clone(),
            title.clone(),
            source.clone(),
            description.clone(),
        ]);
        csv.push_str(&row);
        csv.push('\n');
    }

    Ok(csv)
}

pub fn parse_csv(content: &str) -> Result<Vec<Vec<String>>, ForensicError> {
    let mut result = vec![];
    let mut current_row = Vec::new();
    let mut current_field = String::new();
    let mut in_quotes = false;

    for ch in content.chars() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
            }
            ',' if !in_quotes => {
                current_row.push(current_field.clone());
                current_field.clear();
            }
            '\n' if !in_quotes => {
                current_row.push(current_field.clone());
                result.push(current_row.clone());
                current_row.clear();
                current_field.clear();
            }
            _ => {
                current_field.push(ch);
            }
        }
    }

    if !current_field.is_empty() || !current_row.is_empty() {
        current_row.push(current_field);
        result.push(current_row);
    }

    Ok(result)
}
