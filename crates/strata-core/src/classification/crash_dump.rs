pub fn get_crash_dumps() -> Vec<CrashDump> {
    vec![]
}

#[derive(Debug, Clone, Default)]
pub struct CrashDump {
    pub dump_type: String,
    pub file_path: String,
    pub size: u64,
    pub timestamp: u64,
    pub process_name: Option<String>,
    pub pid: Option<u32>,
}

pub fn parse_crash_dump() -> Vec<DumpAnalysis> {
    vec![]
}

#[derive(Debug, Clone, Default)]
pub struct DumpAnalysis {
    pub dump_path: String,
    pub architecture: String,
    pub os_version: String,
    pub exception_code: Option<u32>,
    pub exception_address: Option<u64>,
    pub modules: Vec<DumpModule>,
}

#[derive(Debug, Clone, Default)]
pub struct DumpModule {
    pub base: u64,
    pub size: u64,
    pub name: String,
    pub path: String,
}

pub fn get_hung_applications() -> Vec<HungApp> {
    vec![]
}

#[derive(Debug, Clone, Default)]
pub struct HungApp {
    pub window_title: String,
    pub process_name: String,
    pub pid: u32,
    pub hung_time: u64,
}

pub fn get_wer_reports() -> Vec<WerReport> {
    vec![]
}

#[derive(Debug, Clone, Default)]
pub struct WerReport {
    pub report_id: String,
    pub app_name: String,
    pub app_version: String,
    pub event_time: u64,
    pub bucket_path: String,
}
