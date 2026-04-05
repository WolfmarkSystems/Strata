use forensic_engine::parser::ParserRegistry;
use forensic_engine::virtualization::VfsEntry;
use std::path::PathBuf;

#[test]
fn test_register_default_parsers() {
    let mut registry = ParserRegistry::new();
    registry.register_default_parsers();

    // There are 50+ parsers registered in default
    assert!(
        registry.parsers().len() > 20,
        "Should have registered many default parsers"
    );
}

#[test]
fn test_find_files_for_parser_pattern_matching() {
    let registry = ParserRegistry::new();

    // Create a mock parser struct that implements ArtifactParser just for testing pattern matching
    struct MockParser;
    impl forensic_engine::parser::ArtifactParser for MockParser {
        fn name(&self) -> &str {
            "MockParser"
        }

        fn artifact_type(&self) -> &str {
            "mock"
        }

        fn target_patterns(&self) -> Vec<&str> {
            vec!["*.evtx", "NTUSER.DAT"]
        }

        fn parse_file(
            &self,
            _path: &std::path::Path,
            _data: &[u8],
        ) -> Result<
            Vec<forensic_engine::parser::ParsedArtifact>,
            forensic_engine::parser::ParserError,
        > {
            Ok(vec![])
        }
    }

    let entries = vec![
        VfsEntry {
            path: PathBuf::from("Windows/System32/winevt/Logs/Security.evtx"),
            name: "Security.evtx".to_string(),
            size: 1024,
            is_dir: false,
            modified: None,
        },
        VfsEntry {
            path: PathBuf::from("Users/Default/NTUSER.DAT"),
            name: "ntuser.dat".to_string(), // Testing case-insensitivity
            size: 2048,
            is_dir: false,
            modified: None,
        },
        VfsEntry {
            path: PathBuf::from("Windows/System32"),
            name: "System32".to_string(),
            size: 0,
            is_dir: true,
            modified: None,
        },
        VfsEntry {
            path: PathBuf::from("random_file.txt"),
            name: "random_file.txt".to_string(),
            size: 10,
            is_dir: false,
            modified: None,
        },
    ];

    let mock = MockParser;
    let matches = registry.find_files_for_parser(&mock, &entries);

    assert_eq!(matches.len(), 2);
    assert_eq!(
        matches[0],
        PathBuf::from("Windows/System32/winevt/Logs/Security.evtx")
    );
    assert_eq!(matches[1], PathBuf::from("Users/Default/NTUSER.DAT"));
}
