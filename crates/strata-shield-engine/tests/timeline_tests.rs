use forensic_engine::timeline::{TimelineEntry, TimelineManager};
use std::path::Path;

fn get_memory_manager() -> TimelineManager {
    TimelineManager::new(Path::new(":memory:")).expect("Failed to create in-memory TimelineManager")
}

#[test]
fn test_timeline_manager_initialization() {
    let manager = get_memory_manager();
    assert_eq!(manager.get_count().unwrap(), 0);
}

#[test]
fn test_timeline_insertion_and_query() {
    let mut manager = get_memory_manager();

    let entry = TimelineEntry::new(
        Some(1234567890),
        "test_artifact".to_string(),
        "A test description".to_string(),
        "/path/to/test.db".to_string(),
        serde_json::json!({"key": "value"}),
    );

    let id = manager
        .insert_entry(&entry)
        .expect("Failed to insert entry");
    assert!(id > 0);

    assert_eq!(manager.get_count().unwrap(), 1);

    let entries = manager
        .get_initial_entries(10)
        .expect("Failed to get entries");
    assert_eq!(entries.len(), 1);

    let retrieved = &entries[0];
    assert_eq!(retrieved.timestamp, Some(1234567890));
    assert_eq!(retrieved.artifact_type, "test_artifact");
    assert_eq!(retrieved.description, "A test description");
    assert_eq!(retrieved.source_path, "/path/to/test.db");
    assert_eq!(retrieved.json_data["key"], "value");
}

#[test]
fn test_timeline_get_initial_entries_limit() {
    let mut manager = get_memory_manager();

    for i in 0..5 {
        let entry = TimelineEntry::new(
            Some(1000 + i),
            "test_artifact".to_string(),
            format!("Test {}", i),
            "/path/to/test.db".to_string(),
            serde_json::json!({}),
        );
        manager.insert_entry(&entry).unwrap();
    }

    assert_eq!(manager.get_count().unwrap(), 5);

    let expected_limit = 3;
    let entries = manager.get_initial_entries(expected_limit).unwrap();

    assert_eq!(entries.len(), expected_limit);
}
