use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Note {
    pub id: String,
    pub case_id: String,
    pub created_at: u64,
    pub modified_at: u64,
    pub title: String,
    pub content: String,
    pub tags: Vec<String>,
    pub exhibit_refs: Vec<ExhibitRef>,
    pub linked_objects: Vec<LinkedObject>,
    pub screenshot_paths: Vec<String>,
    pub reviewed: bool,
    pub reviewer: Option<String>,
    pub reviewed_at: Option<u64>,
}

impl Note {
    pub fn new(case_id: &str, title: &str, content: &str) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Self {
            id: Uuid::new_v4().to_string(),
            case_id: case_id.to_string(),
            created_at: now,
            modified_at: now,
            title: title.to_string(),
            content: content.to_string(),
            tags: Vec::new(),
            exhibit_refs: Vec::new(),
            linked_objects: Vec::new(),
            screenshot_paths: Vec::new(),
            reviewed: false,
            reviewer: None,
            reviewed_at: None,
        }
    }

    pub fn add_tag(&mut self, tag: &str) {
        if !self.tags.contains(&tag.to_string()) {
            self.tags.push(tag.to_string());
            self.modified_at = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
        }
    }

    pub fn add_exhibit(&mut self, exhibit: ExhibitRef) {
        self.exhibit_refs.push(exhibit);
        self.modified_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    pub fn add_linked_object(&mut self, object: LinkedObject) {
        self.linked_objects.push(object);
        self.modified_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    pub fn add_screenshot(&mut self, path: &str) {
        self.screenshot_paths.push(path.to_string());
        self.modified_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    pub fn mark_reviewed(&mut self, reviewer: &str) {
        self.reviewed = true;
        self.reviewer = Some(reviewer.to_string());
        self.reviewed_at = Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExhibitRef {
    pub id: String,
    pub exhibit_id: String,
    pub reference_type: ExhibitRefType,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExhibitRefType {
    File,
    Artifact,
    TimelineEvent,
    SearchResult,
    Image,
    Text,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkedObject {
    pub object_type: String,
    pub object_id: String,
    pub path: Option<String>,
    pub hash_sha256: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Exhibit {
    pub id: String,
    pub case_id: String,
    pub created_at: u64,
    pub created_by: String,
    pub name: String,
    pub description: String,
    pub exhibit_type: ExhibitType,
    pub source_evidence_id: Option<String>,
    pub file_path: Option<String>,
    pub data: Option<Vec<u8>>,
    pub hash_md5: Option<String>,
    pub hash_sha1: Option<String>,
    pub hash_sha256: Option<String>,
    pub tags: Vec<String>,
    pub notes: String,
    pub screenshot_paths: Vec<String>,
    pub metadata: HashMap<String, String>,
    pub packet_index: usize,
}

impl Exhibit {
    pub fn new(case_id: &str, created_by: &str, name: &str, exhibit_type: ExhibitType) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            case_id: case_id.to_string(),
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            created_by: created_by.to_string(),
            name: name.to_string(),
            description: String::new(),
            exhibit_type,
            source_evidence_id: None,
            file_path: None,
            data: None,
            hash_md5: None,
            hash_sha1: None,
            hash_sha256: None,
            tags: Vec::new(),
            notes: String::new(),
            screenshot_paths: Vec::new(),
            metadata: HashMap::new(),
            packet_index: 0,
        }
    }

    pub fn with_file(mut self, path: &str) -> Self {
        self.file_path = Some(path.to_string());
        self
    }

    pub fn with_data(mut self, data: Vec<u8>) -> Self {
        self.data = Some(data);
        self
    }

    pub fn with_hash(mut self, md5: &str, sha1: &str, sha256: &str) -> Self {
        self.hash_md5 = Some(md5.to_string());
        self.hash_sha1 = Some(sha1.to_string());
        self.hash_sha256 = Some(sha256.to_string());
        self
    }

    pub fn add_screenshot(&mut self, path: &str) {
        self.screenshot_paths.push(path.to_string());
    }

    pub fn add_tag(&mut self, tag: &str) {
        if !self.tags.contains(&tag.to_string()) {
            self.tags.push(tag.to_string());
        }
    }

    pub fn set_metadata(&mut self, key: &str, value: &str) {
        self.metadata.insert(key.to_string(), value.to_string());
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExhibitType {
    File,
    Image,
    Text,
    WebArchive,
    Email,
    ChatMessage,
    Document,
    Registry,
    Memory,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExhibitPacket {
    pub id: String,
    pub case_id: String,
    pub created_at: u64,
    pub created_by: String,
    pub name: String,
    pub description: String,
    pub exhibits: Vec<Exhibit>,
    pub notes: Vec<Note>,
    pub total_files: usize,
    pub total_size_bytes: u64,
    pub export_path: Option<String>,
}

impl ExhibitPacket {
    pub fn new(case_id: &str, created_by: &str, name: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            case_id: case_id.to_string(),
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            created_by: created_by.to_string(),
            name: name.to_string(),
            description: String::new(),
            exhibits: Vec::new(),
            notes: Vec::new(),
            total_files: 0,
            total_size_bytes: 0,
            export_path: None,
        }
    }

    pub fn add_exhibit(&mut self, exhibit: Exhibit) {
        self.total_files += 1;
        if let Some(ref data) = exhibit.data {
            self.total_size_bytes += data.len() as u64;
        }
        self.exhibits.push(exhibit);
    }

    pub fn add_note(&mut self, note: Note) {
        self.notes.push(note);
    }

    pub fn set_export_path(&mut self, path: &str) {
        self.export_path = Some(path.to_string());
    }
}

pub struct NotesManager {
    case_id: String,
    notes: HashMap<String, Note>,
    exhibits: HashMap<String, Exhibit>,
    packets: HashMap<String, ExhibitPacket>,
}

impl NotesManager {
    pub fn new(case_id: &str) -> Self {
        Self {
            case_id: case_id.to_string(),
            notes: HashMap::new(),
            exhibits: HashMap::new(),
            packets: HashMap::new(),
        }
    }

    pub fn create_note(&mut self, title: &str, content: &str) -> String {
        let note = Note::new(&self.case_id, title, content);
        let id = note.id.clone();
        self.notes.insert(id.clone(), note);
        id
    }

    pub fn get_note(&self, id: &str) -> Option<&Note> {
        self.notes.get(id)
    }

    pub fn get_note_mut(&mut self, id: &str) -> Option<&mut Note> {
        self.notes.get_mut(id)
    }

    pub fn update_note(&mut self, id: &str, title: &str, content: &str) -> bool {
        if let Some(note) = self.notes.get_mut(id) {
            note.title = title.to_string();
            note.content = content.to_string();
            note.modified_at = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            true
        } else {
            false
        }
    }

    pub fn delete_note(&mut self, id: &str) -> bool {
        self.notes.remove(id).is_some()
    }

    pub fn list_notes(&self) -> Vec<&Note> {
        self.notes.values().collect()
    }

    pub fn create_exhibit(
        &mut self,
        name: &str,
        exhibit_type: ExhibitType,
        created_by: &str,
    ) -> String {
        let exhibit = Exhibit::new(&self.case_id, created_by, name, exhibit_type);
        let id = exhibit.id.clone();
        self.exhibits.insert(id.clone(), exhibit);
        id
    }

    pub fn get_exhibit(&self, id: &str) -> Option<&Exhibit> {
        self.exhibits.get(id)
    }

    pub fn get_exhibit_mut(&mut self, id: &str) -> Option<&mut Exhibit> {
        self.exhibits.get_mut(id)
    }

    pub fn delete_exhibit(&mut self, id: &str) -> bool {
        self.exhibits.remove(id).is_some()
    }

    pub fn list_exhibits(&self) -> Vec<&Exhibit> {
        self.exhibits.values().collect()
    }

    pub fn create_packet(&mut self, name: &str, created_by: &str) -> String {
        let packet = ExhibitPacket::new(&self.case_id, created_by, name);
        let id = packet.id.clone();
        self.packets.insert(id.clone(), packet);
        id
    }

    pub fn get_packet(&self, id: &str) -> Option<&ExhibitPacket> {
        self.packets.get(id)
    }

    pub fn get_packet_mut(&mut self, id: &str) -> Option<&mut ExhibitPacket> {
        self.packets.get_mut(id)
    }

    pub fn add_to_packet(
        &mut self,
        packet_id: &str,
        exhibit_id: &str,
        note_id: Option<&str>,
    ) -> bool {
        if let Some(packet) = self.packets.get_mut(packet_id) {
            if let Some(exhibit) = self.exhibits.get(exhibit_id) {
                packet.add_exhibit(exhibit.clone());
                if let Some(nid) = note_id {
                    if let Some(note) = self.notes.get(nid) {
                        packet.add_note(note.clone());
                    }
                }
                return true;
            }
        }
        false
    }

    pub fn list_packets(&self) -> Vec<&ExhibitPacket> {
        self.packets.values().collect()
    }

    pub fn search_notes(&self, query: &str) -> Vec<&Note> {
        let query_lower = query.to_lowercase();
        self.notes
            .values()
            .filter(|note| {
                note.title.to_lowercase().contains(&query_lower)
                    || note.content.to_lowercase().contains(&query_lower)
                    || note
                        .tags
                        .iter()
                        .any(|t| t.to_lowercase().contains(&query_lower))
            })
            .collect()
    }

    pub fn get_notes_by_tag(&self, tag: &str) -> Vec<&Note> {
        self.notes
            .values()
            .filter(|note| note.tags.contains(&tag.to_string()))
            .collect()
    }

    pub fn get_unreviewed_notes(&self) -> Vec<&Note> {
        self.notes.values().filter(|note| !note.reviewed).collect()
    }

    pub fn get_exhibits_by_tag(&self, tag: &str) -> Vec<&Exhibit> {
        self.exhibits
            .values()
            .filter(|exhibit| exhibit.tags.contains(&tag.to_string()))
            .collect()
    }
}
