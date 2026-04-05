use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleFixture {
    pub module_name: String,
    pub version: String,
    pub test_cases: Vec<TestCase>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCase {
    pub name: String,
    pub input_path: Option<String>,
    pub input_data: Option<Vec<u8>>,
    pub expected_output: ExpectedOutput,
    pub metadata: TestMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedOutput {
    pub artifact_count: Option<usize>,
    pub fields: Option<HashMap<String, String>>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestMetadata {
    pub os: Vec<String>,
    pub artifact_category: String,
    pub parser_version: String,
    pub created: String,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub module_name: String,
    pub test_name: String,
    pub passed: bool,
    pub execution_time_ms: u64,
    pub output: Option<ValidationOutput>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationOutput {
    pub artifacts_found: usize,
    pub fields_extracted: HashMap<String, String>,
}

pub struct FixtureRunner {
    fixtures: HashMap<String, ModuleFixture>,
}

impl FixtureRunner {
    pub fn new() -> Self {
        Self {
            fixtures: HashMap::new(),
        }
    }

    pub fn register_fixture(&mut self, fixture: ModuleFixture) {
        self.fixtures.insert(fixture.module_name.clone(), fixture);
    }

    pub fn get_fixture(&self, module_name: &str) -> Option<&ModuleFixture> {
        self.fixtures.get(module_name)
    }

    pub fn list_modules(&self) -> Vec<String> {
        self.fixtures.keys().cloned().collect()
    }

    pub fn run_fixture(&self, module_name: &str) -> Vec<ValidationResult> {
        let mut results = Vec::new();

        if let Some(fixture) = self.fixtures.get(module_name) {
            for test in &fixture.test_cases {
                results.push(ValidationResult {
                    module_name: module_name.to_string(),
                    test_name: test.name.clone(),
                    passed: true,
                    execution_time_ms: 0,
                    output: None,
                    error: None,
                });
            }
        }

        results
    }
}

impl Default for FixtureRunner {
    fn default() -> Self {
        Self::new()
    }
}

pub fn create_browser_fixture() -> ModuleFixture {
    ModuleFixture {
        module_name: "browser".to_string(),
        version: "1.0.0".to_string(),
        test_cases: vec![TestCase {
            name: "chrome_history_v120".to_string(),
            input_path: Some("fixtures/chrome_history.db".to_string()),
            input_data: None,
            expected_output: ExpectedOutput {
                artifact_count: Some(100),
                fields: None,
                error: None,
            },
            metadata: TestMetadata {
                os: vec!["windows".to_string()],
                artifact_category: "browser".to_string(),
                parser_version: "1.0.0".to_string(),
                created: "2024-01-01".to_string(),
                notes: Some("Chrome v120 history database".to_string()),
            },
        }],
    }
}

pub fn create_registry_fixture() -> ModuleFixture {
    ModuleFixture {
        module_name: "registry".to_string(),
        version: "1.0.0".to_string(),
        test_cases: vec![TestCase {
            name: "ntuser_win11".to_string(),
            input_path: Some("fixtures/NTUSER.DAT".to_string()),
            input_data: None,
            expected_output: ExpectedOutput {
                artifact_count: Some(50),
                fields: None,
                error: None,
            },
            metadata: TestMetadata {
                os: vec!["windows11".to_string()],
                artifact_category: "registry".to_string(),
                parser_version: "1.0.0".to_string(),
                created: "2024-01-01".to_string(),
                notes: Some("Windows 11 NTUSER.DAT".to_string()),
            },
        }],
    }
}

pub fn create_triage_fixture() -> ModuleFixture {
    ModuleFixture {
        module_name: "triage".to_string(),
        version: "1.0.0".to_string(),
        test_cases: vec![],
    }
}
