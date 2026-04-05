use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Screenshot {
    pub id: String,
    pub case_id: String,
    pub capture_type: ScreenshotType,
    pub created_at: u64,
    pub created_by: String,
    pub width: u32,
    pub height: u32,
    pub format: ImageFormat,
    pub data: Option<Vec<u8>>,
    pub file_path: Option<String>,
    pub thumbnail_path: Option<String>,
    pub description: String,
    pub tags: Vec<String>,
    pub linked_objects: Vec<ScreenshotLink>,
    pub is_annotated: bool,
    pub annotations: Vec<Annotation>,
}

impl Screenshot {
    pub fn new(case_id: &str, created_by: &str, capture_type: ScreenshotType) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            case_id: case_id.to_string(),
            capture_type,
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            created_by: created_by.to_string(),
            width: 0,
            height: 0,
            format: ImageFormat::Png,
            data: None,
            file_path: None,
            thumbnail_path: None,
            description: String::new(),
            tags: Vec::new(),
            linked_objects: Vec::new(),
            is_annotated: false,
            annotations: Vec::new(),
        }
    }

    pub fn with_dimensions(mut self, width: u32, height: u32) -> Self {
        self.width = width;
        self.height = height;
        self
    }

    pub fn with_format(mut self, format: ImageFormat) -> Self {
        self.format = format;
        self
    }

    pub fn with_data(mut self, data: Vec<u8>) -> Self {
        self.data = Some(data);
        self
    }

    pub fn with_file_path(mut self, path: &str) -> Self {
        self.file_path = Some(path.to_string());
        self
    }

    pub fn with_thumbnail(mut self, path: &str) -> Self {
        self.thumbnail_path = Some(path.to_string());
        self
    }

    pub fn with_description(mut self, description: &str) -> Self {
        self.description = description.to_string();
        self
    }

    pub fn add_tag(&mut self, tag: &str) {
        if !self.tags.contains(&tag.to_string()) {
            self.tags.push(tag.to_string());
        }
    }

    pub fn add_link(&mut self, link: ScreenshotLink) {
        self.linked_objects.push(link);
    }

    pub fn add_annotation(&mut self, annotation: Annotation) {
        self.annotations.push(annotation);
        self.is_annotated = true;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ScreenshotType {
    FullScreen,
    Window,
    Region,
    Artifact,
    FilePreview,
    HexView,
    Timeline,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ImageFormat {
    Png,
    Jpeg,
    Bmp,
    WebP,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScreenshotLink {
    pub object_type: String,
    pub object_id: String,
    pub description: Option<String>,
}

impl ScreenshotLink {
    pub fn new(object_type: &str, object_id: &str) -> Self {
        Self {
            object_type: object_type.to_string(),
            object_id: object_id.to_string(),
            description: None,
        }
    }

    pub fn with_description(mut self, description: &str) -> Self {
        self.description = Some(description.to_string());
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Annotation {
    pub id: String,
    pub annotation_type: AnnotationType,
    pub x: f32,
    pub y: f32,
    pub width: Option<f32>,
    pub height: Option<f32>,
    pub color: String,
    pub text: Option<String>,
    pub font_size: Option<u32>,
}

impl Annotation {
    pub fn new(annotation_type: AnnotationType, x: f32, y: f32) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            annotation_type,
            x,
            y,
            width: None,
            height: None,
            color: "#FF0000".to_string(),
            text: None,
            font_size: None,
        }
    }

    pub fn with_size(mut self, width: f32, height: f32) -> Self {
        self.width = Some(width);
        self.height = Some(height);
        self
    }

    pub fn with_color(mut self, color: &str) -> Self {
        self.color = color.to_string();
        self
    }

    pub fn with_text(mut self, text: &str) -> Self {
        self.text = Some(text.to_string());
        self
    }

    pub fn with_font_size(mut self, size: u32) -> Self {
        self.font_size = Some(size);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AnnotationType {
    Rectangle,
    Arrow,
    Line,
    Text,
    Highlight,
    Blur,
    Number,
}

pub struct ScreenshotManager {
    _case_id: String,
    screenshots: HashMap<String, Screenshot>,
}

impl ScreenshotManager {
    pub fn new(case_id: &str) -> Self {
        Self {
            _case_id: case_id.to_string(),
            screenshots: HashMap::new(),
        }
    }

    pub fn capture(&mut self, screenshot: Screenshot) -> String {
        let id = screenshot.id.clone();
        self.screenshots.insert(id.clone(), screenshot);
        id
    }

    pub fn get_screenshot(&self, id: &str) -> Option<&Screenshot> {
        self.screenshots.get(id)
    }

    pub fn get_screenshot_mut(&mut self, id: &str) -> Option<&mut Screenshot> {
        self.screenshots.get_mut(id)
    }

    pub fn delete_screenshot(&mut self, id: &str) -> bool {
        self.screenshots.remove(id).is_some()
    }

    pub fn list_screenshots(&self) -> Vec<&Screenshot> {
        self.screenshots.values().collect()
    }

    pub fn list_by_type(&self, screenshot_type: ScreenshotType) -> Vec<&Screenshot> {
        self.screenshots
            .values()
            .filter(|s| s.capture_type == screenshot_type)
            .collect()
    }

    pub fn list_by_tag(&self, tag: &str) -> Vec<&Screenshot> {
        self.screenshots
            .values()
            .filter(|s| s.tags.contains(&tag.to_string()))
            .collect()
    }

    pub fn search(&self, query: &str) -> Vec<&Screenshot> {
        let query_lower = query.to_lowercase();
        self.screenshots
            .values()
            .filter(|s| {
                s.description.to_lowercase().contains(&query_lower)
                    || s.tags
                        .iter()
                        .any(|t| t.to_lowercase().contains(&query_lower))
            })
            .collect()
    }

    pub fn get_linked_screenshots(&self, object_id: &str) -> Vec<&Screenshot> {
        self.screenshots
            .values()
            .filter(|s| s.linked_objects.iter().any(|l| l.object_id == object_id))
            .collect()
    }

    pub fn get_annotated(&self) -> Vec<&Screenshot> {
        self.screenshots
            .values()
            .filter(|s| s.is_annotated)
            .collect()
    }

    pub fn count(&self) -> usize {
        self.screenshots.len()
    }

    pub fn get_by_date_range(&self, start: u64, end: u64) -> Vec<&Screenshot> {
        self.screenshots
            .values()
            .filter(|s| s.created_at >= start && s.created_at <= end)
            .collect()
    }
}
