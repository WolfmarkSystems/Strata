use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bookmark {
    pub id: String,
    pub case_id: String,
    pub created_at: u64,
    pub modified_at: u64,
    pub created_by: String,
    pub title: String,
    pub description: String,
    pub tags: Vec<String>,
    pub objects: Vec<BookmarkObject>,
    pub parent_id: Option<String>,
    pub color: Option<String>,
    pub icon: Option<String>,
    pub reviewed: bool,
    pub reviewer: Option<String>,
    pub reviewed_at: Option<u64>,
    pub notes: String,
    pub custom_fields: HashMap<String, String>,
}

impl Bookmark {
    pub fn new(case_id: &str, created_by: &str, title: &str) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Self {
            id: Uuid::new_v4().to_string(),
            case_id: case_id.to_string(),
            created_at: now,
            modified_at: now,
            created_by: created_by.to_string(),
            title: title.to_string(),
            description: String::new(),
            tags: Vec::new(),
            objects: Vec::new(),
            parent_id: None,
            color: None,
            icon: None,
            reviewed: false,
            reviewer: None,
            reviewed_at: None,
            notes: String::new(),
            custom_fields: HashMap::new(),
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

    pub fn remove_tag(&mut self, tag: &str) {
        self.tags.retain(|t| t != tag);
        self.modified_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    pub fn add_object(&mut self, object: BookmarkObject) {
        self.objects.push(object);
        self.modified_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    pub fn set_parent(&mut self, parent_id: &str) {
        self.parent_id = Some(parent_id.to_string());
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

    pub fn set_color(&mut self, color: &str) {
        self.color = Some(color.to_string());
        self.modified_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    pub fn set_description(&mut self, description: &str) {
        self.description = description.to_string();
        self.modified_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    pub fn set_notes(&mut self, notes: &str) {
        self.notes = notes.to_string();
        self.modified_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    pub fn set_custom_field(&mut self, key: &str, value: &str) {
        self.custom_fields
            .insert(key.to_string(), value.to_string());
        self.modified_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BookmarkObject {
    pub object_type: BookmarkObjectType,
    pub object_id: String,
    pub path: Option<String>,
    pub file_name: Option<String>,
    pub size: Option<u64>,
    pub hash_sha256: Option<String>,
    pub evidence_id: Option<String>,
    pub volume_id: Option<String>,
    pub offset: Option<u64>,
    pub metadata: HashMap<String, String>,
}

impl BookmarkObject {
    pub fn new(object_type: BookmarkObjectType, object_id: &str) -> Self {
        Self {
            object_type,
            object_id: object_id.to_string(),
            path: None,
            file_name: None,
            size: None,
            hash_sha256: None,
            evidence_id: None,
            volume_id: None,
            offset: None,
            metadata: HashMap::new(),
        }
    }

    pub fn with_path(mut self, path: &str) -> Self {
        self.path = Some(path.to_string());
        self
    }

    pub fn with_file_name(mut self, name: &str) -> Self {
        self.file_name = Some(name.to_string());
        self
    }

    pub fn with_size(mut self, size: u64) -> Self {
        self.size = Some(size);
        self
    }

    pub fn with_hash(mut self, hash: &str) -> Self {
        self.hash_sha256 = Some(hash.to_string());
        self
    }

    pub fn with_evidence(mut self, evidence_id: &str) -> Self {
        self.evidence_id = Some(evidence_id.to_string());
        self
    }

    pub fn with_volume(mut self, volume_id: &str) -> Self {
        self.volume_id = Some(volume_id.to_string());
        self
    }

    pub fn with_offset(mut self, offset: u64) -> Self {
        self.offset = Some(offset);
        self
    }

    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum BookmarkObjectType {
    File,
    Directory,
    MftEntry,
    RegistryKey,
    RegistryValue,
    EventLog,
    Artifact,
    TimelineEvent,
    Process,
    Connection,
    MemoryRegion,
    DiskSector,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tag {
    pub id: String,
    pub case_id: String,
    pub name: String,
    pub color: String,
    pub description: String,
    pub created_at: u64,
    pub created_by: String,
    pub usage_count: u32,
}

impl Tag {
    pub fn new(case_id: &str, created_by: &str, name: &str, color: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            case_id: case_id.to_string(),
            name: name.to_string(),
            color: color.to_string(),
            description: String::new(),
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            created_by: created_by.to_string(),
            usage_count: 0,
        }
    }

    pub fn increment_usage(&mut self) {
        self.usage_count += 1;
    }

    pub fn decrement_usage(&mut self) {
        if self.usage_count > 0 {
            self.usage_count -= 1;
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BookmarkFolder {
    pub id: String,
    pub case_id: String,
    pub parent_id: Option<String>,
    pub name: String,
    pub description: String,
    pub color: Option<String>,
    pub icon: Option<String>,
    pub created_at: u64,
    pub created_by: String,
    pub bookmark_count: u32,
}

impl BookmarkFolder {
    pub fn new(case_id: &str, created_by: &str, name: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            case_id: case_id.to_string(),
            parent_id: None,
            name: name.to_string(),
            description: String::new(),
            color: None,
            icon: None,
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            created_by: created_by.to_string(),
            bookmark_count: 0,
        }
    }

    pub fn set_parent(&mut self, parent_id: &str) {
        self.parent_id = Some(parent_id.to_string());
    }
}

pub struct BookmarkManager {
    case_id: String,
    bookmarks: HashMap<String, Bookmark>,
    tags: HashMap<String, Tag>,
    folders: HashMap<String, BookmarkFolder>,
}

impl BookmarkManager {
    pub fn new(case_id: &str) -> Self {
        Self {
            case_id: case_id.to_string(),
            bookmarks: HashMap::new(),
            tags: HashMap::new(),
            folders: HashMap::new(),
        }
    }

    pub fn create_bookmark(&mut self, created_by: &str, title: &str) -> String {
        let bookmark = Bookmark::new(&self.case_id, created_by, title);
        let id = bookmark.id.clone();
        self.bookmarks.insert(id.clone(), bookmark);
        id
    }

    pub fn get_bookmark(&self, id: &str) -> Option<&Bookmark> {
        self.bookmarks.get(id)
    }

    pub fn get_bookmark_mut(&mut self, id: &str) -> Option<&mut Bookmark> {
        self.bookmarks.get_mut(id)
    }

    pub fn update_bookmark(&mut self, id: &str, title: &str, description: &str) -> bool {
        if let Some(bookmark) = self.bookmarks.get_mut(id) {
            bookmark.title = title.to_string();
            bookmark.description = description.to_string();
            bookmark.modified_at = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            true
        } else {
            false
        }
    }

    pub fn delete_bookmark(&mut self, id: &str) -> bool {
        self.bookmarks.remove(id).is_some()
    }

    pub fn list_bookmarks(&self) -> Vec<&Bookmark> {
        self.bookmarks.values().collect()
    }

    pub fn get_bookmarks_by_tag(&self, tag: &str) -> Vec<&Bookmark> {
        self.bookmarks
            .values()
            .filter(|b| b.tags.contains(&tag.to_string()))
            .collect()
    }

    pub fn get_bookmarks_by_folder(&self, folder_id: Option<&str>) -> Vec<&Bookmark> {
        self.bookmarks
            .values()
            .filter(|b| b.parent_id.as_deref() == folder_id)
            .collect()
    }

    pub fn get_unreviewed_bookmarks(&self) -> Vec<&Bookmark> {
        self.bookmarks.values().filter(|b| !b.reviewed).collect()
    }

    pub fn search_bookmarks(&self, query: &str) -> Vec<&Bookmark> {
        let query_lower = query.to_lowercase();
        self.bookmarks
            .values()
            .filter(|b| {
                b.title.to_lowercase().contains(&query_lower)
                    || b.description.to_lowercase().contains(&query_lower)
                    || b.notes.to_lowercase().contains(&query_lower)
                    || b.tags
                        .iter()
                        .any(|t| t.to_lowercase().contains(&query_lower))
            })
            .collect()
    }

    pub fn create_tag(&mut self, created_by: &str, name: &str, color: &str) -> String {
        let tag = Tag::new(&self.case_id, created_by, name, color);
        let id = tag.id.clone();
        self.tags.insert(id.clone(), tag);
        id
    }

    pub fn get_tag(&self, id: &str) -> Option<&Tag> {
        self.tags.get(id)
    }

    pub fn get_tag_by_name(&self, name: &str) -> Option<&Tag> {
        self.tags.values().find(|t| t.name == name)
    }

    pub fn delete_tag(&mut self, id: &str) -> bool {
        self.tags.remove(id).is_some()
    }

    pub fn list_tags(&self) -> Vec<&Tag> {
        self.tags.values().collect()
    }

    pub fn get_or_create_tag(&mut self, created_by: &str, name: &str, color: &str) -> String {
        if let Some(tag) = self.tags.values().find(|t| t.name == name) {
            return tag.id.clone();
        }
        self.create_tag(created_by, name, color)
    }

    pub fn create_folder(&mut self, created_by: &str, name: &str) -> String {
        let folder = BookmarkFolder::new(&self.case_id, created_by, name);
        let id = folder.id.clone();
        self.folders.insert(id.clone(), folder);
        id
    }

    pub fn get_folder(&self, id: &str) -> Option<&BookmarkFolder> {
        self.folders.get(id)
    }

    pub fn delete_folder(&mut self, id: &str) -> bool {
        self.folders.remove(id).is_some()
    }

    pub fn list_folders(&self) -> Vec<&BookmarkFolder> {
        self.folders.values().collect()
    }

    pub fn get_bookmarks_count(&self) -> usize {
        self.bookmarks.len()
    }

    pub fn get_tags_count(&self) -> usize {
        self.tags.len()
    }

    pub fn get_folders_count(&self) -> usize {
        self.folders.len()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BookmarkExport {
    pub bookmarks: Vec<Bookmark>,
    pub tags: Vec<Tag>,
    pub folders: Vec<BookmarkFolder>,
    pub export_timestamp: u64,
}

impl BookmarkManager {
    pub fn export_all(&self) -> BookmarkExport {
        BookmarkExport {
            bookmarks: self.bookmarks.values().cloned().collect(),
            tags: self.tags.values().cloned().collect(),
            folders: self.folders.values().cloned().collect(),
            export_timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
}
