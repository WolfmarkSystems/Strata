use std::collections::HashMap;

/// Storage for known Unified Log message templates
/// In a production environment, this would be populated from the Catalog chunks
pub struct LogTemplateStore {
    pub templates: HashMap<u64, String>,
}

impl Default for LogTemplateStore {
    fn default() -> Self {
        Self::new()
    }
}

impl LogTemplateStore {
    pub fn new() -> Self {
        let mut templates = HashMap::new();
        // Common macOS templates
        templates.insert(0x1a2b, "User logged in: %s from %s".to_string());
        templates.insert(0x3c4d, "Application %s started with PID %d".to_string());
        templates.insert(0x5e6f, "Kernel: %s internal error %x".to_string());

        Self { templates }
    }

    pub fn resolve(&self, template_id: u64, args: &[String]) -> String {
        if let Some(tmpl) = self.templates.get(&template_id) {
            let mut result = tmpl.clone();
            for arg in args {
                if let Some(pos) = result.find('%') {
                    // Very simple placeholder replacement
                    result.replace_range(pos..pos + 2, arg);
                }
            }
            result
        } else {
            format!(
                "Unknown Template ID: 0x{:x} (Args: {:?})",
                template_id, args
            )
        }
    }
}
