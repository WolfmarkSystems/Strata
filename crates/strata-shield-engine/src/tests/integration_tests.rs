#[cfg(test)]
use crate::memory::EProcess;
#[cfg(test)]
use crate::parsers::media::project_vic::VicsEntry;
#[cfg(test)]
use crate::parsers::social::snapchat::SnapGeo;
#[cfg(test)]
use crate::parsers::social::tiktok::TikTokDraft;

#[test]
fn test_eprocess_structure_mocking() {
    let mock_process = EProcess {
        process_id: 1337,
        process_name: String::from("svchost.exe"),
        parent_pid: 4,
        start_time: 1629472312,
    };
    assert_eq!(mock_process.process_name, "svchost.exe");
    assert_ne!(mock_process.parent_pid, mock_process.process_id);
}

#[test]
fn test_project_vic_ingestion_mocking() {
    let entry = VicsEntry {
        md5: String::from("1a79a4d60de6718e8e5b326e338ae533"),
        sha1: String::from("9fb219abf51cf6cf874fa77074e2df45a7556017"),
        category: String::from("CSAM_Tier1"),
    };
    assert_eq!(entry.category, "CSAM_Tier1");
}

#[test]
fn test_tiktok_draft_recovery() {
    let draft = TikTokDraft {
        temp_path: String::from(
            "/private/var/mobile/Containers/Data/Application/TikTok/tmp/video_cache",
        ),
        created: 1712435422,
    };
    assert!(draft.temp_path.contains("TikTok"));
}

#[test]
fn test_snapmap_geofencing() {
    let geo = SnapGeo {
        lat: 34.0522,
        lon: -118.2437,
        timestamp: 1712435400,
    };
    assert_eq!(geo.lat, 34.0522);
}
