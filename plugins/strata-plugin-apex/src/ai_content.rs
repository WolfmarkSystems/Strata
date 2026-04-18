//! AI-1 — AI-generated content detection.
//!
//! Combines three signals to flag AI-generated images:
//!   1. EXIF `Software` field matching known tool strings.
//!   2. PNG `tEXt` / `iTXt` chunks carrying Stable Diffusion / ComfyUI
//!      parameters (prompt, negative prompt, model, seed).
//!   3. Installed-tool artifacts on disk
//!      (`~/stable-diffusion-webui/`, `~/ComfyUI/`,
//!      `~/.cache/huggingface/` …) that confirm the suspect's
//!      AI toolchain.
//!
//! Also provides a separate record for chatbot interaction logs
//! (ChatGPT / Claude / Gemini) so the plugin can report "what did
//! the user ask an AI to do?" alongside the generated images.
//!
//! Zero `.unwrap()`, zero `unsafe {}`, zero `println!` per CLAUDE.md.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AIGeneratedContent {
    pub file_path: String,
    pub detection_method: String,
    pub ai_tool: Option<String>,
    pub prompt: Option<String>,
    pub negative_prompt: Option<String>,
    pub model_used: Option<String>,
    pub generation_timestamp: Option<DateTime<Utc>>,
    pub confidence: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AIInteractionLog {
    pub platform: String,
    pub timestamp: DateTime<Utc>,
    pub user_query: Option<String>,
    pub ai_response_summary: Option<String>,
    pub source: String,
}

/// Known AI-tool strings to match against the EXIF Software field.
const EXIF_SOFTWARE_MARKERS: &[(&str, &str)] = &[
    ("stable diffusion", "Stable Diffusion"),
    ("midjourney", "Midjourney"),
    ("dall", "DALL-E"),
    ("comfyui", "ComfyUI"),
    ("automatic1111", "Automatic1111"),
    ("leonardo", "Leonardo.ai"),
    ("firefly", "Adobe Firefly"),
    ("flux", "Flux"),
    ("ideogram", "Ideogram"),
    ("runway", "Runway"),
];

/// Classify an EXIF Software field. Returns the canonical tool name
/// if any marker matches, else None.
pub fn ai_tool_from_exif_software(software: &str) -> Option<&'static str> {
    let lower = software.to_ascii_lowercase();
    EXIF_SOFTWARE_MARKERS
        .iter()
        .find(|(needle, _)| lower.contains(needle))
        .map(|(_, name)| *name)
}

/// Parse a Stable Diffusion / Automatic1111 parameters blob
/// (typical PNG tEXt with key `parameters`). Returns prompt +
/// negative prompt + model name + sampler, all optional.
pub fn parse_sd_parameters(blob: &str) -> AIGeneratedContent {
    let (prompt, negative_prompt, model) = sd_extract_fields(blob);
    AIGeneratedContent {
        file_path: String::new(),
        detection_method: "PNGMetadata".into(),
        ai_tool: Some("Stable Diffusion".into()),
        prompt,
        negative_prompt,
        model_used: model,
        generation_timestamp: None,
        confidence: 0.9,
    }
}

fn sd_extract_fields(blob: &str) -> (Option<String>, Option<String>, Option<String>) {
    // Stable Diffusion convention:
    //   <prompt>\nNegative prompt: <negative>\nSteps: ..., Model: <model>, ...
    let mut lines = blob.lines();
    let prompt_line = lines.next().map(|s| s.trim().to_string());
    let mut negative: Option<String> = None;
    let mut model: Option<String> = None;
    for line in lines {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Negative prompt:") {
            negative = Some(rest.trim().into());
        }
        // Metadata CSV line e.g. "Steps: 30, Model: realisticVision..., Sampler: DPM++"
        for chunk in trimmed.split(',') {
            let chunk = chunk.trim();
            if let Some(rest) = chunk.strip_prefix("Model:") {
                model = Some(rest.trim().into());
            }
        }
    }
    (prompt_line.filter(|s| !s.is_empty()), negative, model)
}

/// Parse a ComfyUI workflow JSON — returns prompt and model-name hits.
pub fn parse_comfyui_workflow(json: &str) -> Option<AIGeneratedContent> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let mut prompt: Option<String> = None;
    let mut model: Option<String> = None;
    walk(&v, &mut |val| {
        if let Some(obj) = val.as_object() {
            if let Some(cls) = obj.get("class_type").and_then(|x| x.as_str()) {
                if cls.eq_ignore_ascii_case("CLIPTextEncode") {
                    if let Some(p) = obj
                        .get("inputs")
                        .and_then(|i| i.get("text"))
                        .and_then(|t| t.as_str())
                    {
                        if prompt.is_none() {
                            prompt = Some(p.to_string());
                        }
                    }
                }
                if cls.eq_ignore_ascii_case("CheckpointLoaderSimple") {
                    if let Some(m) = obj
                        .get("inputs")
                        .and_then(|i| i.get("ckpt_name"))
                        .and_then(|t| t.as_str())
                    {
                        model = Some(m.to_string());
                    }
                }
            }
        }
    });
    Some(AIGeneratedContent {
        file_path: String::new(),
        detection_method: "PNGMetadata:ComfyUI".into(),
        ai_tool: Some("ComfyUI".into()),
        prompt,
        negative_prompt: None,
        model_used: model,
        generation_timestamp: None,
        confidence: 0.95,
    })
}

fn walk<F: FnMut(&serde_json::Value)>(v: &serde_json::Value, f: &mut F) {
    f(v);
    match v {
        serde_json::Value::Array(arr) => {
            for x in arr {
                walk(x, f);
            }
        }
        serde_json::Value::Object(obj) => {
            for (_, x) in obj {
                walk(x, f);
            }
        }
        _ => {}
    }
}

/// Detect local AI-tool installations by walking caller-supplied
/// home-dir roots for the canonical folder names.
pub fn detect_local_ai_tools(home: &Path) -> Vec<String> {
    let probes = [
        ("stable-diffusion-webui", "Automatic1111"),
        ("ComfyUI", "ComfyUI"),
        (".cache/huggingface", "Hugging Face cache"),
        ("ollama", "Ollama"),
        (".tortoise-tts", "Tortoise TTS"),
    ];
    probes
        .iter()
        .filter(|(dir, _)| home.join(dir).exists())
        .map(|(_, label)| (*label).to_string())
        .collect()
}

/// Parse a ChatGPT / Claude / Gemini desktop-app interaction log
/// JSONL stream.
pub fn parse_interaction_log(platform: &str, line: &str, source: &str) -> Option<AIInteractionLog> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    let ts = v.get("timestamp")?.as_str()?;
    let timestamp = DateTime::parse_from_rfc3339(ts).ok()?.with_timezone(&Utc);
    Some(AIInteractionLog {
        platform: platform.into(),
        timestamp,
        user_query: v.get("user_query").and_then(|x| x.as_str()).map(String::from),
        ai_response_summary: v
            .get("ai_response_summary")
            .and_then(|x| x.as_str())
            .map(String::from),
        source: source.into(),
    })
}

/// When a CSAM hash-set hit lands on a file we've also flagged as
/// AI-generated, the legal framework differs. Returns a
/// case-report-ready flag that the CSAM plugin can plumb through.
pub fn csam_ai_generated_flag(is_csam: bool, is_ai_generated: bool) -> Option<&'static str> {
    if is_csam && is_ai_generated {
        Some("AI-Generated CSAM (distinct legal framework applies)")
    } else {
        None
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn exif_software_matches_catalog() {
        assert_eq!(
            ai_tool_from_exif_software("Stable Diffusion 1.5 + Automatic1111"),
            Some("Stable Diffusion")
        );
        assert_eq!(ai_tool_from_exif_software("Adobe Photoshop"), None);
        assert_eq!(ai_tool_from_exif_software("Midjourney"), Some("Midjourney"));
    }

    #[test]
    fn sd_parameters_parser_pulls_prompt_and_model() {
        let blob = "beautiful landscape, mountains\nNegative prompt: blurry, low quality\nSteps: 30, Sampler: DPM++ 2M, Model: realisticVisionV20";
        let r = parse_sd_parameters(blob);
        assert_eq!(r.prompt.as_deref(), Some("beautiful landscape, mountains"));
        assert_eq!(r.negative_prompt.as_deref(), Some("blurry, low quality"));
        assert_eq!(r.model_used.as_deref(), Some("realisticVisionV20"));
        assert!(r.confidence >= 0.9);
    }

    #[test]
    fn comfyui_workflow_extraction() {
        let json = r#"{"1":{"class_type":"CheckpointLoaderSimple",
            "inputs":{"ckpt_name":"sd_xl_base.safetensors"}},
            "2":{"class_type":"CLIPTextEncode",
            "inputs":{"text":"a cat on mars"}}}"#;
        let r = parse_comfyui_workflow(json).expect("parsed");
        assert_eq!(r.prompt.as_deref(), Some("a cat on mars"));
        assert_eq!(r.model_used.as_deref(), Some("sd_xl_base.safetensors"));
    }

    #[test]
    fn detects_local_ai_tools() {
        let tmp = tempfile::tempdir().expect("tmp");
        fs::create_dir_all(tmp.path().join("stable-diffusion-webui")).expect("mk");
        fs::create_dir_all(tmp.path().join("ComfyUI")).expect("mk");
        let tools = detect_local_ai_tools(tmp.path());
        assert!(tools.iter().any(|t| t == "Automatic1111"));
        assert!(tools.iter().any(|t| t == "ComfyUI"));
    }

    #[test]
    fn interaction_log_jsonl_parser() {
        let line = r#"{"timestamp":"2026-04-10T10:00:00Z",
            "user_query":"write a phishing email",
            "ai_response_summary":"declined to help"}"#;
        let r = parse_interaction_log("ChatGPT", line, "Desktop").expect("parsed");
        assert_eq!(r.platform, "ChatGPT");
        assert_eq!(r.user_query.as_deref(), Some("write a phishing email"));
    }

    #[test]
    fn csam_ai_flag_fires_only_on_both_conditions() {
        assert_eq!(
            csam_ai_generated_flag(true, true),
            Some("AI-Generated CSAM (distinct legal framework applies)")
        );
        assert_eq!(csam_ai_generated_flag(true, false), None);
        assert_eq!(csam_ai_generated_flag(false, true), None);
    }

    #[test]
    fn bad_input_is_empty() {
        assert!(parse_interaction_log("X", "nope", "src").is_none());
        assert!(parse_comfyui_workflow("not-json").is_none());
    }
}
