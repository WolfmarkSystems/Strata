use std::process::Command;

fn load_contracts() -> serde_json::Value {
    serde_json::from_str(include_str!("golden_contracts.json"))
        .expect("golden contracts should parse")
}

fn json_path_exists(value: &serde_json::Value, path: &str) -> bool {
    let mut current = value;
    for segment in path.split('.') {
        match current {
            serde_json::Value::Object(map) => {
                if let Some(next) = map.get(segment) {
                    current = next;
                } else {
                    return false;
                }
            }
            _ => return false,
        }
    }
    true
}

fn assert_contract_paths(
    command: &str,
    payload: &serde_json::Value,
    contracts: &serde_json::Value,
) {
    let required = contracts
        .get(command)
        .and_then(|v| v.get("required_paths"))
        .and_then(|v| v.as_array())
        .expect("required_paths should exist");

    for path in required {
        let path_str = path.as_str().expect("path should be string");
        assert!(
            json_path_exists(payload, path_str),
            "missing required JSON contract path '{}' for command '{}'",
            path_str,
            command
        );
    }
}

fn run_cli_with_json_result(args: &[&str], json_result_path: &str) -> serde_json::Value {
    let _ = strata_fs::remove_file(json_result_path);
    let mut cmd_args = vec!["run", "-p", "strata-shield-cli", "--"];
    cmd_args.extend_from_slice(args);
    cmd_args.extend_from_slice(&["--json-result", json_result_path, "--quiet"]);

    let output = Command::new("cargo")
        .args(&cmd_args)
        .output()
        .expect("failed to execute forensic_cli command");
    assert_eq!(
        output.status.code(),
        Some(0),
        "command should succeed: {:?}\nstderr: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );

    let content =
        strata_fs::read_to_string(json_result_path).expect("json result should be readable");
    serde_json::from_str(&content).expect("json result should parse")
}

#[test]
fn golden_contract_recent_execution() {
    let contracts = load_contracts();
    let test_dir = "tests_temp_contract_recent_execution";
    let _ = strata_fs::remove_dir_all(test_dir);
    strata_fs::create_dir_all(test_dir).unwrap();

    let prefetch_dir = format!("{}/prefetch", test_dir);
    let jumplist_file = format!("{}/sample.automaticdestinations-ms", test_dir);
    let shortcuts_base = format!("{}/shortcuts", test_dir);
    strata_fs::create_dir_all(&prefetch_dir).unwrap();
    strata_fs::create_dir_all(&shortcuts_base).unwrap();

    let prefetch_path = format!("{}/CMD.EXE-11111111.pf", prefetch_dir);
    let mut pf_data = vec![0u8; 512];
    pf_data[0..4].copy_from_slice(b"SCCA");
    pf_data[4..8].copy_from_slice(&0x1Eu32.to_le_bytes());
    let ft = (11_644_473_600u64 + 1_700_000_000u64) * 10_000_000u64;
    pf_data[0x80..0x88].copy_from_slice(&ft.to_le_bytes());
    strata_fs::write(&prefetch_path, pf_data).unwrap();
    strata_fs::write(
        &jumplist_file,
        b"DestList\0C:\\Windows\\System32\\cmd.exe\0",
    )
    .unwrap();

    let json_result_path = format!("{}/recent_execution_contract.json", test_dir);
    let payload = run_cli_with_json_result(
        &[
            "recent-execution",
            "--prefetch-dir",
            &prefetch_dir,
            "--jumplist-path",
            &jumplist_file,
            "--shortcuts-base",
            &shortcuts_base,
            "--limit",
            "50",
        ],
        &json_result_path,
    );
    assert_contract_paths("recent-execution", &payload, &contracts);

    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn golden_contract_registry_persistence() {
    let contracts = load_contracts();
    let test_dir = "tests_temp_contract_registry_persistence";
    let _ = strata_fs::remove_dir_all(test_dir);
    strata_fs::create_dir_all(test_dir).unwrap();

    let autorun_reg = format!("{}/autorun.reg", test_dir);
    let bam_reg = format!("{}/bam.reg", test_dir);
    let amcache_reg = format!("{}/amcache.reg", test_dir);
    let tasks_root = format!("{}/tasks", test_dir);
    let task_xml = format!("{}/task.xml", tasks_root);
    strata_fs::create_dir_all(&tasks_root).unwrap();

    strata_fs::write(
        &autorun_reg,
        r#"
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run]
"BadApp"="C:\\Tools\\bad.exe --silent"
"#,
    )
    .unwrap();
    let bam_ft = (1_700_000_000u64 + 11_644_473_600) * 10_000_000;
    strata_fs::write(
        &bam_reg,
        format!(
            r#"
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21]
"C:\\Tools\\bad.exe"=qword:{bam_ft:016x}
"#
        ),
    )
    .unwrap();
    strata_fs::write(
        &amcache_reg,
        r#"
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateChange\PackageList\Amcache\Files\0001]
"LowerCaseLongPath"="C:\\Tools\\bad.exe"
"#,
    )
    .unwrap();
    strata_fs::write(
        &task_xml,
        r#"<Task><Actions><Exec><Command>C:\Tools\bad.exe</Command></Exec></Actions></Task>"#,
    )
    .unwrap();

    let json_result_path = format!("{}/registry_persistence_contract.json", test_dir);
    let payload = run_cli_with_json_result(
        &[
            "registry-persistence",
            "--autorun-reg",
            &autorun_reg,
            "--bam-reg",
            &bam_reg,
            "--amcache-reg",
            &amcache_reg,
            "--tasks-root",
            &tasks_root,
            "--limit",
            "50",
        ],
        &json_result_path,
    );
    assert_contract_paths("registry-persistence", &payload, &contracts);

    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn golden_contract_registry_core_user_hives() {
    let contracts = load_contracts();
    let test_dir = "tests_temp_contract_registry_core_user_hives";
    let _ = strata_fs::remove_dir_all(test_dir);
    strata_fs::create_dir_all(test_dir).unwrap();

    let runmru = format!("{}/runmru.reg", test_dir);
    let opensave = format!("{}/mru2.reg", test_dir);
    let userassist = format!("{}/userassist.reg", test_dir);
    let recentdocs = format!("{}/recentdocs.reg", test_dir);

    strata_fs::write(
        &runmru,
        r#"[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU]
"MRUList"="ab"
"a"="cmd.exe"
"b"="powershell.exe -nop"
"#,
    )
    .unwrap();
    strata_fs::write(
        &opensave,
        r#"[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSaveMRU\txt]
"a"="C:\\Temp\\notes.txt"
"#,
    )
    .unwrap();
    let expected_unix = 1_700_000_222u64;
    let filetime = (expected_unix + 11_644_473_600) * 10_000_000;
    let mut ua_bytes = [0u8; 68];
    ua_bytes[4..8].copy_from_slice(&3u32.to_le_bytes());
    ua_bytes[60..68].copy_from_slice(&filetime.to_le_bytes());
    let ua_payload = ua_bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(",");
    strata_fs::write(
        &userassist,
        format!(
            r#"[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\Count]
"P:\\Jvaqbjf\\pzq.rkr"=hex:{ua_payload}
"#
        ),
    )
    .unwrap();
    strata_fs::write(
        &recentdocs,
        r#"[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs]
"a"="C:\\Docs\\report.txt"
"#,
    )
    .unwrap();

    let json_result_path = format!("{}/registry_core_user_hives_contract.json", test_dir);
    let payload = run_cli_with_json_result(
        &[
            "registry-core-user-hives",
            "--runmru-reg",
            &runmru,
            "--opensave-reg",
            &opensave,
            "--userassist-reg",
            &userassist,
            "--recentdocs-reg",
            &recentdocs,
            "--limit",
            "50",
        ],
        &json_result_path,
    );
    assert_contract_paths("registry-core-user-hives", &payload, &contracts);

    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn golden_contract_shimcache_deep() {
    let contracts = load_contracts();
    let test_dir = "tests_temp_contract_shimcache_deep";
    let _ = strata_fs::remove_dir_all(test_dir);
    strata_fs::create_dir_all(test_dir).unwrap();

    let appcompat = format!("{}/appcompat.reg", test_dir);
    strata_fs::write(
        &appcompat,
        r#"[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache]
"C:\Windows\System32\cmd.exe"="1700000000"
"#,
    )
    .unwrap();

    let json_result_path = format!("{}/shimcache_deep_contract.json", test_dir);
    let payload = run_cli_with_json_result(
        &[
            "shimcache-deep",
            "--appcompat-reg",
            &appcompat,
            "--limit",
            "50",
        ],
        &json_result_path,
    );
    assert_contract_paths("shimcache-deep", &payload, &contracts);

    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn golden_contract_amcache_deep() {
    let contracts = load_contracts();
    let test_dir = "tests_temp_contract_amcache_deep";
    let _ = strata_fs::remove_dir_all(test_dir);
    strata_fs::create_dir_all(test_dir).unwrap();

    let amcache = format!("{}/amcache.reg", test_dir);
    let amcache_ft = (1_700_200_000u64 + 11_644_473_600) * 10_000_000;
    strata_fs::write(
        &amcache,
        format!(
            r#"[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateChange\PackageList\Amcache\Files\0001]
"LowerCaseLongPath"="C:\Tools\bad.exe"
"Sha1"="00112233445566778899aabbccddeeff00112233"
"LastWriteTime"=qword:{amcache_ft:016x}
"#
        ),
    )
    .unwrap();

    let json_result_path = format!("{}/amcache_deep_contract.json", test_dir);
    let payload = run_cli_with_json_result(
        &["amcache-deep", "--amcache-reg", &amcache, "--limit", "50"],
        &json_result_path,
    );
    assert_contract_paths("amcache-deep", &payload, &contracts);

    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn golden_contract_bam_dam_activity() {
    let contracts = load_contracts();
    let test_dir = "tests_temp_contract_bam_dam_activity";
    let _ = strata_fs::remove_dir_all(test_dir);
    strata_fs::create_dir_all(test_dir).unwrap();

    let bam = format!("{}/bam.reg", test_dir);
    let bam_ft = (1_700_300_000u64 + 11_644_473_600) * 10_000_000;
    strata_fs::write(
        &bam,
        format!(
            r#"[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21]
"C:\Windows\System32\cmd.exe"=qword:{bam_ft:016x}
"#
        ),
    )
    .unwrap();

    let json_result_path = format!("{}/bam_dam_activity_contract.json", test_dir);
    let payload = run_cli_with_json_result(
        &["bam-dam-activity", "--bam-reg", &bam, "--limit", "50"],
        &json_result_path,
    );
    assert_contract_paths("bam-dam-activity", &payload, &contracts);

    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn golden_contract_services_drivers_artifacts() {
    let contracts = load_contracts();
    let test_dir = "tests_temp_contract_services_drivers_artifacts";
    let _ = strata_fs::remove_dir_all(test_dir);
    strata_fs::create_dir_all(test_dir).unwrap();

    let services = format!("{}/services.reg", test_dir);
    strata_fs::write(
        &services,
        r#"[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BadSvc]
"ImagePath"="C:\Users\Public\badhost.exe"
"Start"=dword:00000002
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BadSvc\Parameters]
"ServiceDll"="C:\Users\Public\bad.dll"
"#,
    )
    .unwrap();

    let json_result_path = format!("{}/services_drivers_contract.json", test_dir);
    let payload = run_cli_with_json_result(
        &[
            "services-drivers-artifacts",
            "--services-reg",
            &services,
            "--limit",
            "50",
        ],
        &json_result_path,
    );
    assert_contract_paths("services-drivers-artifacts", &payload, &contracts);

    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn golden_contract_scheduled_tasks_artifacts() {
    let contracts = load_contracts();
    let test_dir = "tests_temp_contract_scheduled_tasks_artifacts";
    let _ = strata_fs::remove_dir_all(test_dir);
    strata_fs::create_dir_all(test_dir).unwrap();

    let tasks_root = format!("{}/tasks", test_dir);
    strata_fs::create_dir_all(&tasks_root).unwrap();
    let task_xml = format!("{}/task.xml", tasks_root);
    strata_fs::write(
        &task_xml,
        r#"<Task><LastRunTime>2026-03-10T09:30:00</LastRunTime><Actions><Exec><Command>C:\Windows\System32\cmd.exe</Command><Arguments>/c whoami</Arguments></Exec></Actions></Task>"#,
    )
    .unwrap();

    let json_result_path = format!("{}/scheduled_tasks_contract.json", test_dir);
    let payload = run_cli_with_json_result(
        &[
            "scheduled-tasks-artifacts",
            "--tasks-root",
            &tasks_root,
            "--limit",
            "50",
        ],
        &json_result_path,
    );
    assert_contract_paths("scheduled-tasks-artifacts", &payload, &contracts);

    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn golden_contract_wmi_persistence_activity() {
    let contracts = load_contracts();
    let test_dir = "tests_temp_contract_wmi_persistence_activity";
    let _ = strata_fs::remove_dir_all(test_dir);
    strata_fs::create_dir_all(test_dir).unwrap();

    let persist = format!("{}/persistence.json", test_dir);
    let traces = format!("{}/traces.json", test_dir);
    let instances = format!("{}/instances.json", test_dir);
    strata_fs::write(
        &persist,
        r#"[{"consumer":"cmd.exe /c beacon.ps1","filter":"SELECT * FROM __InstanceCreationEvent"}]"#,
    )
    .unwrap();
    strata_fs::write(
        &traces,
        r#"[{"timestamp":"1700001111","namespace":"root\\subscription"}]"#,
    )
    .unwrap();
    strata_fs::write(
        &instances,
        r#"[{"class":"Win32_Process","properties":{"Name":"cmd.exe"}}]"#,
    )
    .unwrap();

    let json_result_path = format!("{}/wmi_persistence_contract.json", test_dir);
    let payload = run_cli_with_json_result(
        &[
            "wmi-persistence-activity",
            "--persist-input",
            &persist,
            "--traces-input",
            &traces,
            "--instances-input",
            &instances,
            "--limit",
            "50",
        ],
        &json_result_path,
    );
    assert_contract_paths("wmi-persistence-activity", &payload, &contracts);

    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn golden_contract_ntfs_mft_fidelity() {
    let contracts = load_contracts();
    let test_dir = "tests_temp_contract_ntfs_mft_fidelity";
    let _ = strata_fs::remove_dir_all(test_dir);
    strata_fs::create_dir_all(test_dir).unwrap();

    let mft_input = format!("{}/mft.json", test_dir);
    strata_fs::write(
        &mft_input,
        r#"[
  {"record_number":42,"sequence_number":1,"file_name":"cmd.exe","modified_time":1700001111}
]"#,
    )
    .unwrap();

    let json_result_path = format!("{}/ntfs_mft_contract.json", test_dir);
    let payload = run_cli_with_json_result(
        &[
            "ntfs-mft-fidelity",
            "--mft-input",
            &mft_input,
            "--limit",
            "50",
        ],
        &json_result_path,
    );
    assert_contract_paths("ntfs-mft-fidelity", &payload, &contracts);

    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn golden_contract_usn_journal_fidelity() {
    let contracts = load_contracts();
    let test_dir = "tests_temp_contract_usn_journal_fidelity";
    let _ = strata_fs::remove_dir_all(test_dir);
    strata_fs::create_dir_all(test_dir).unwrap();

    let usn_input = format!("{}/usn.csv", test_dir);
    strata_fs::write(
        &usn_input,
        "timestamp,usn,reason,file_name,file_path\n2026-03-10T10:00:00Z,42,FILE_DELETE,cmd.exe,C:\\Windows\\System32\\cmd.exe\n",
    )
    .unwrap();

    let json_result_path = format!("{}/usn_journal_contract.json", test_dir);
    let payload = run_cli_with_json_result(
        &[
            "usn-journal-fidelity",
            "--usn-input",
            &usn_input,
            "--limit",
            "50",
        ],
        &json_result_path,
    );
    assert_contract_paths("usn-journal-fidelity", &payload, &contracts);

    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn golden_contract_ntfs_logfile_signals() {
    let contracts = load_contracts();
    let test_dir = "tests_temp_contract_ntfs_logfile_signals";
    let _ = strata_fs::remove_dir_all(test_dir);
    strata_fs::create_dir_all(test_dir).unwrap();

    let input_path = format!("{}/logfile.json", test_dir);
    strata_fs::write(
        &input_path,
        r#"{"signals":[{"offset":12,"signal":"file_delete","context":"Delete C:\\Temp\\cmd.exe","timestamp_unix":1700001234,"process_path":"C:/Windows/System32/cmd.exe"}]}"#,
    )
    .unwrap();

    let json_result_path = format!("{}/ntfs_logfile_contract.json", test_dir);
    let payload = run_cli_with_json_result(
        &[
            "ntfs-logfile-signals",
            "--input",
            &input_path,
            "--limit",
            "50",
        ],
        &json_result_path,
    );
    assert_contract_paths("ntfs-logfile-signals", &payload, &contracts);

    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn golden_contract_recycle_bin_artifacts() {
    let contracts = load_contracts();
    let test_dir = "tests_temp_contract_recycle_bin_artifacts";
    let _ = strata_fs::remove_dir_all(test_dir);
    strata_fs::create_dir_all(test_dir).unwrap();

    let input_path = format!("{}/recycle.json", test_dir);
    strata_fs::write(
        &input_path,
        r#"{"entries":[{"file_name":"cmd.exe","deleted_time":1700002000,"file_size":128,"original_path":"C:/Temp/cmd.exe","owner_sid":"S-1-5-21-1000"}]}"#,
    )
    .unwrap();

    let json_result_path = format!("{}/recycle_contract.json", test_dir);
    let payload = run_cli_with_json_result(
        &[
            "recycle-bin-artifacts",
            "--input",
            &input_path,
            "--limit",
            "50",
        ],
        &json_result_path,
    );
    assert_contract_paths("recycle-bin-artifacts", &payload, &contracts);

    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn golden_contract_prefetch_fidelity() {
    let contracts = load_contracts();
    let test_dir = "tests_temp_contract_prefetch_fidelity";
    let _ = strata_fs::remove_dir_all(test_dir);
    strata_fs::create_dir_all(test_dir).unwrap();

    let input_path = format!("{}/prefetch.json", test_dir);
    strata_fs::write(
        &input_path,
        r#"{"records":[{"program_name":"CMD.EXE","last_run_time":1700003333,"run_count":3,"files_referenced":["C:/Windows/System32/cmd.exe"],"directories_referenced":["C:/Windows/System32"],"volumes_referenced":["C:"]}]}"#,
    )
    .unwrap();

    let json_result_path = format!("{}/prefetch_contract.json", test_dir);
    let payload = run_cli_with_json_result(
        &["prefetch-fidelity", "--input", &input_path, "--limit", "50"],
        &json_result_path,
    );
    assert_contract_paths("prefetch-fidelity", &payload, &contracts);

    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn golden_contract_jumplist_fidelity() {
    let contracts = load_contracts();
    let test_dir = "tests_temp_contract_jumplist_fidelity";
    let _ = strata_fs::remove_dir_all(test_dir);
    strata_fs::create_dir_all(test_dir).unwrap();

    let input_path = format!("{}/jumplist.json", test_dir);
    strata_fs::write(
        &input_path,
        r#"{"entries":[{"entry_type":"recent","target_path":"C:/Windows/System32/cmd.exe","timestamp_unix":1700010000,"app_id":"shell","mru_rank":1}]}"#,
    )
    .unwrap();

    let json_result_path = format!("{}/jumplist_contract.json", test_dir);
    let payload = run_cli_with_json_result(
        &["jumplist-fidelity", "--input", &input_path, "--limit", "50"],
        &json_result_path,
    );
    assert_contract_paths("jumplist-fidelity", &payload, &contracts);

    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn golden_contract_lnk_shortcut_fidelity() {
    let contracts = load_contracts();
    let test_dir = "tests_temp_contract_lnk_shortcut_fidelity";
    let _ = strata_fs::remove_dir_all(test_dir);
    strata_fs::create_dir_all(test_dir).unwrap();

    let input_path = format!("{}/lnk.json", test_dir);
    strata_fs::write(
        &input_path,
        r#"{"records":[{"path":"C:/Users/lab/Desktop/cmd.lnk","target_path":"C:/Windows/System32/cmd.exe","arguments":"/c whoami","write_time_unix":1700010100}]}"#,
    )
    .unwrap();

    let json_result_path = format!("{}/lnk_contract.json", test_dir);
    let payload = run_cli_with_json_result(
        &[
            "lnk-shortcut-fidelity",
            "--input",
            &input_path,
            "--limit",
            "50",
        ],
        &json_result_path,
    );
    assert_contract_paths("lnk-shortcut-fidelity", &payload, &contracts);

    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn golden_contract_browser_forensics() {
    let contracts = load_contracts();
    let test_dir = "tests_temp_contract_browser_forensics";
    let _ = strata_fs::remove_dir_all(test_dir);
    strata_fs::create_dir_all(test_dir).unwrap();

    let input_path = format!("{}/browser.json", test_dir);
    strata_fs::write(
        &input_path,
        r#"{"records":[{"url":"https://example.test","title":"Example","browser":"chrome","timestamp_unix":1700062001}]}"#,
    )
    .unwrap();

    let json_result_path = format!("{}/browser_forensics_contract.json", test_dir);
    let payload = run_cli_with_json_result(
        &["browser-forensics", "--input", &input_path, "--limit", "50"],
        &json_result_path,
    );
    assert_contract_paths("browser-forensics", &payload, &contracts);

    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn golden_contract_rdp_remote_access() {
    let contracts = load_contracts();
    let test_dir = "tests_temp_contract_rdp_remote_access";
    let _ = strata_fs::remove_dir_all(test_dir);
    strata_fs::create_dir_all(test_dir).unwrap();

    let input_path = format!("{}/rdp.json", test_dir);
    strata_fs::write(
        &input_path,
        r#"{"records":[{"target_host":"srv1","timestamp_unix":1700062002,"username":"analyst"}]}"#,
    )
    .unwrap();

    let json_result_path = format!("{}/rdp_remote_access_contract.json", test_dir);
    let payload = run_cli_with_json_result(
        &["rdp-remote-access", "--input", &input_path, "--limit", "50"],
        &json_result_path,
    );
    assert_contract_paths("rdp-remote-access", &payload, &contracts);

    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn golden_contract_usb_device_history() {
    let contracts = load_contracts();
    let test_dir = "tests_temp_contract_usb_device_history";
    let _ = strata_fs::remove_dir_all(test_dir);
    strata_fs::create_dir_all(test_dir).unwrap();

    let input_path = format!("{}/usb.json", test_dir);
    strata_fs::write(
        &input_path,
        r#"{"records":[{"vendor_id":"0781","product_id":"5581","serial_number":"ABC123","timestamp_unix":1700062003}]}"#,
    )
    .unwrap();

    let json_result_path = format!("{}/usb_device_history_contract.json", test_dir);
    let payload = run_cli_with_json_result(
        &[
            "usb-device-history",
            "--input",
            &input_path,
            "--limit",
            "50",
        ],
        &json_result_path,
    );
    assert_contract_paths("usb-device-history", &payload, &contracts);

    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn golden_contract_restore_shadow_copies() {
    let contracts = load_contracts();
    let test_dir = "tests_temp_contract_restore_shadow_copies";
    let _ = strata_fs::remove_dir_all(test_dir);
    strata_fs::create_dir_all(test_dir).unwrap();

    let input_path = format!("{}/restore_shadow.json", test_dir);
    strata_fs::write(
        &input_path,
        r#"{"records":[{"source":"restore-point","event_type":"checkpoint","id":5,"snapshot_time":1700062004}]}"#,
    )
    .unwrap();

    let json_result_path = format!("{}/restore_shadow_copies_contract.json", test_dir);
    let payload = run_cli_with_json_result(
        &[
            "restore-shadow-copies",
            "--input",
            &input_path,
            "--limit",
            "50",
        ],
        &json_result_path,
    );
    assert_contract_paths("restore-shadow-copies", &payload, &contracts);

    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn golden_contract_user_activity_mru() {
    let contracts = load_contracts();
    let test_dir = "tests_temp_contract_user_activity_mru";
    let _ = strata_fs::remove_dir_all(test_dir);
    strata_fs::create_dir_all(test_dir).unwrap();

    let input_path = format!("{}/user_activity_mru.json", test_dir);
    strata_fs::write(
        &input_path,
        r#"{"records":[{"source":"runmru","event_type":"runmru-command","timestamp_unix":1700062005,"command":"C:/Windows/System32/cmd.exe"}]}"#,
    )
    .unwrap();

    let json_result_path = format!("{}/user_activity_mru_contract.json", test_dir);
    let payload = run_cli_with_json_result(
        &["user-activity-mru", "--input", &input_path, "--limit", "50"],
        &json_result_path,
    );
    assert_contract_paths("user-activity-mru", &payload, &contracts);

    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn golden_contract_timeline_correlation_qa() {
    let contracts = load_contracts();
    let test_dir = "tests_temp_contract_timeline_correlation_qa";
    let _ = strata_fs::remove_dir_all(test_dir);
    strata_fs::create_dir_all(test_dir).unwrap();

    let input_path = format!("{}/timeline_correlation_qa.json", test_dir);
    strata_fs::write(
        &input_path,
        r#"{"events":[{"source":"execution","event_type":"prefetch-run","timestamp_unix":1700062006,"severity":"info","executable_name":"cmd.exe"}]}"#,
    )
    .unwrap();

    let json_result_path = format!("{}/timeline_correlation_qa_contract.json", test_dir);
    let payload = run_cli_with_json_result(
        &[
            "timeline-correlation-qa",
            "--input",
            &input_path,
            "--limit",
            "50",
        ],
        &json_result_path,
    );
    assert_contract_paths("timeline-correlation-qa", &payload, &contracts);

    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn golden_contract_timeline() {
    use forensic_engine::case::database::CaseDatabase;
    use std::path::Path;

    let contracts = load_contracts();
    let test_dir = "tests_temp_contract_timeline";
    let _ = strata_fs::remove_dir_all(test_dir);
    strata_fs::create_dir_all(test_dir).unwrap();

    let db_path = format!("{}/test_case.sqlite", test_dir);
    let case_id = "test_case_contract_timeline";
    let _db = CaseDatabase::create(case_id, Path::new(&db_path)).expect("Failed to create case db");

    let prefetch_dir = format!("{}/prefetch", test_dir);
    let jumplist_file = format!("{}/sample.automaticdestinations-ms", test_dir);
    let shortcuts_base = format!("{}/shortcuts", test_dir);
    strata_fs::create_dir_all(&prefetch_dir).unwrap();
    strata_fs::create_dir_all(&shortcuts_base).unwrap();

    let prefetch_path = format!("{}/CMD.EXE-11111111.pf", prefetch_dir);
    let mut pf_data = vec![0u8; 512];
    pf_data[0..4].copy_from_slice(b"SCCA");
    pf_data[4..8].copy_from_slice(&0x1Eu32.to_le_bytes());
    let ft = (11_644_473_600u64 + 1_700_000_000u64) * 10_000_000u64;
    pf_data[0x80..0x88].copy_from_slice(&ft.to_le_bytes());
    strata_fs::write(&prefetch_path, pf_data).unwrap();
    strata_fs::write(
        &jumplist_file,
        b"DestList\0C:\\Windows\\System32\\cmd.exe\0",
    )
    .unwrap();

    let json_result_path = format!("{}/timeline_contract.json", test_dir);
    let payload = run_cli_with_json_result(
        &[
            "timeline",
            "--case",
            case_id,
            "--db",
            &db_path,
            "--source",
            "execution",
            "--prefetch-dir",
            &prefetch_dir,
            "--jumplist-path",
            &jumplist_file,
            "--shortcuts-base",
            &shortcuts_base,
            "--limit",
            "50",
        ],
        &json_result_path,
    );
    assert_contract_paths("timeline", &payload, &contracts);

    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn golden_contract_srum() {
    let contracts = load_contracts();
    let test_dir = "tests_temp_contract_srum";
    let _ = strata_fs::remove_dir_all(test_dir);
    strata_fs::create_dir_all(test_dir).unwrap();

    let srum_input = format!("{}/srum.json", test_dir);
    strata_fs::write(
        &srum_input,
        r#"{
  "records": [
    {
      "record_id": 11,
      "provider": "network",
      "record_type": "network-usage",
      "timestamp_utc": "2026-03-10T11:00:00Z",
      "app_name": "cmd.exe",
      "exe_path": "C:\\Windows\\System32\\cmd.exe",
      "user_sid": "S-1-5-21-1000",
      "bytes_in": 10,
      "bytes_out": 20
    }
  ]
}"#,
    )
    .unwrap();

    let json_result_path = format!("{}/srum_contract.json", test_dir);
    let payload = run_cli_with_json_result(
        &["srum", "--input", &srum_input, "--limit", "50"],
        &json_result_path,
    );
    assert_contract_paths("srum", &payload, &contracts);

    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn golden_contract_evtx_security() {
    let contracts = load_contracts();
    let test_dir = "tests_temp_contract_evtx_security";
    let _ = strata_fs::remove_dir_all(test_dir);
    strata_fs::create_dir_all(test_dir).unwrap();

    let evtx_input = format!("{}/Security.evtx", test_dir);
    strata_fs::write(
        &evtx_input,
        r#"<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4624</EventID><Level>4</Level><EventRecordID>100</EventRecordID><TimeCreated SystemTime="2026-03-10T14:00:00.000Z"/></System><EventData><Data Name="TargetUserName">alice</Data></EventData></Event>"#,
    )
    .unwrap();

    let json_result_path = format!("{}/evtx_security_contract.json", test_dir);
    let payload = run_cli_with_json_result(
        &["evtx-security", "--input", &evtx_input, "--limit", "50"],
        &json_result_path,
    );
    assert_contract_paths("evtx-security", &payload, &contracts);

    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn golden_contract_evtx_sysmon() {
    let contracts = load_contracts();
    let test_dir = "tests_temp_contract_evtx_sysmon";
    let _ = strata_fs::remove_dir_all(test_dir);
    strata_fs::create_dir_all(test_dir).unwrap();

    let evtx_input = format!("{}/Sysmon.evtx", test_dir);
    strata_fs::write(
        &evtx_input,
        r#"<Event><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID><Level>4</Level><EventRecordID>77</EventRecordID><TimeCreated SystemTime="2026-03-10T14:00:00.000Z"/></System><EventData><Data Name="Image">C:\Windows\System32\cmd.exe</Data></EventData></Event>"#,
    )
    .unwrap();

    let json_result_path = format!("{}/evtx_sysmon_contract.json", test_dir);
    let payload = run_cli_with_json_result(
        &["evtx-sysmon", "--input", &evtx_input, "--limit", "50"],
        &json_result_path,
    );
    assert_contract_paths("evtx-sysmon", &payload, &contracts);

    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn golden_contract_powershell_artifacts() {
    let contracts = load_contracts();
    let test_dir = "tests_temp_contract_powershell_artifacts";
    let _ = strata_fs::remove_dir_all(test_dir);
    strata_fs::create_dir_all(test_dir).unwrap();

    let history_path = format!("{}/ConsoleHost_history.txt", test_dir);
    let script_log_path = format!("{}/script_block.log", test_dir);
    let events_path = format!("{}/ps_events.json", test_dir);
    let transcripts_dir = format!("{}/Transcripts", test_dir);
    let modules_path = format!("{}/modules.txt", test_dir);
    strata_fs::create_dir_all(&transcripts_dir).unwrap();

    strata_fs::write(&history_path, "Get-Process\nGet-Service\n").unwrap();
    strata_fs::write(
        &script_log_path,
        "1700000000|C:\\Scripts\\run.ps1|-enc AAAA|ok\n1700000000|C:\\Scripts\\run.ps1|-enc AAAA|ok\n",
    )
    .unwrap();
    strata_fs::write(
        &events_path,
        r#"{"records":[{"occurred_utc":"2026-03-11T16:00:00Z","script":"C:\\Windows\\System32\\cmd.exe /c whoami"}]}"#,
    )
    .unwrap();
    strata_fs::write(
        format!("{}/Transcript-1.txt", transcripts_dir),
        "PS C:\\> whoami\nPS> Get-Process\n",
    )
    .unwrap();
    strata_fs::write(
        &modules_path,
        "Az.Accounts|2.14.1|C:\\Modules\\Az.Accounts|Azure module\n",
    )
    .unwrap();

    let json_result_path = format!("{}/powershell_artifacts_contract.json", test_dir);
    let payload = run_cli_with_json_result(
        &[
            "powershell-artifacts",
            "--history",
            &history_path,
            "--script-log",
            &script_log_path,
            "--events",
            &events_path,
            "--transcripts-dir",
            &transcripts_dir,
            "--modules",
            &modules_path,
            "--limit",
            "50",
        ],
        &json_result_path,
    );
    assert_contract_paths("powershell-artifacts", &payload, &contracts);

    let _ = strata_fs::remove_dir_all(test_dir);
}

#[test]
fn golden_contract_defender_artifacts() {
    let contracts = load_contracts();
    let test_dir = "tests_temp_contract_defender_artifacts";
    let _ = strata_fs::remove_dir_all(test_dir);
    strata_fs::create_dir_all(test_dir).unwrap();

    let quarantine_path = format!("{}/quarantine.log", test_dir);
    let scan_history_path = format!("{}/scan_history.log", test_dir);
    let alerts_path = format!("{}/alerts.json", test_dir);
    let indicators_path = format!("{}/indicators.json", test_dir);
    let file_profiles_path = format!("{}/file_profiles.json", test_dir);
    let machine_actions_path = format!("{}/machine_actions.json", test_dir);

    strata_fs::write(
        &quarantine_path,
        "Trojan.Test|C:\\\\Temp\\\\bad.exe|1700000000|High\n",
    )
    .unwrap();
    strata_fs::write(
        &scan_history_path,
        "quick|1700000100|1700000200|completed|1|1\n",
    )
    .unwrap();
    strata_fs::write(
        &alerts_path,
        r#"[{"alert_id":"A-1","title":"Suspicious binary","severity":"high","detected":1700000300,"status":"active","machine_name":"host1"}]"#,
    )
    .unwrap();
    strata_fs::write(
        &indicators_path,
        r#"[{"indicator_type":"fileSha1","value":"001122","action":"alert","created":1700000400}]"#,
    )
    .unwrap();
    strata_fs::write(
        &file_profiles_path,
        r#"[{"sha1":"0011223344","detection_name":"Trojan.Test","first_seen":1700000500,"prevalence":2,"is_malicious":true}]"#,
    )
    .unwrap();
    strata_fs::write(
        &machine_actions_path,
        r#"[{"action_id":"MA-1","machine_id":"M-1","action_type":"isolate","requested":1700000600,"status":"completed"}]"#,
    )
    .unwrap();

    let json_result_path = format!("{}/defender_artifacts_contract.json", test_dir);
    let _ = strata_fs::remove_file(&json_result_path);
    let output = Command::new("cargo")
        .args([
            "run",
            "-p",
            "strata-shield-cli",
            "--",
            "defender-artifacts",
            "--limit",
            "50",
            "--json-result",
            &json_result_path,
            "--quiet",
        ])
        .env("FORENSIC_DEFENDER_QUARANTINE", &quarantine_path)
        .env("FORENSIC_DEFENDER_SCAN_HISTORY", &scan_history_path)
        .env("FORENSIC_DEFENDER_ALERTS", &alerts_path)
        .env("FORENSIC_DEFENDER_INDICATORS", &indicators_path)
        .env("FORENSIC_DEFENDER_FILE_PROFILES", &file_profiles_path)
        .env("FORENSIC_DEFENDER_MACHINE_ACTIONS", &machine_actions_path)
        .output()
        .expect("failed to execute forensic_cli command");

    assert_eq!(
        output.status.code(),
        Some(0),
        "command should succeed\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let content =
        strata_fs::read_to_string(&json_result_path).expect("json result should be readable");
    let payload: serde_json::Value = serde_json::from_str(&content).expect("json should parse");
    assert_contract_paths("defender-artifacts", &payload, &contracts);

    let _ = strata_fs::remove_dir_all(test_dir);
}
