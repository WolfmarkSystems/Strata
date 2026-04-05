use serde::{Deserialize, Serialize};

/// A single KB search result from the bridge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KbHit {
    pub title: String,
    pub snippet: String,
    pub score: f64,
    pub source: String,
}

/// Combined result: artifact keyword matches + KB methodology hits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CombinedSearchResult {
    /// Artifact descriptions that matched the keyword query
    pub artifact_hits: Vec<String>,
    /// KB knowledge base passages relevant to the query
    pub kb_hits: Vec<KbHit>,
    /// Whether the KB bridge was reachable
    pub kb_available: bool,
}

/// Call the KB bridge search endpoint.
/// Returns hits on success, empty vec if bridge is unreachable.
/// Never panics or propagates KB unavailability.
pub fn query_kb_bridge(query: &str, limit: usize) -> Vec<KbHit> {
    let url = std::env::var("STRATA_KB_BRIDGE_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8090".to_string());

    let body = serde_json::json!({
        "query": query,
        "limit": limit.max(1),
    });

    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
    {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let response = match client
        .post(format!("{}/search", url.trim_end_matches('/')))
        .json(&body)
        .send()
    {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    if !response.status().is_success() {
        return Vec::new();
    }

    #[derive(Deserialize)]
    struct BridgeResponse {
        results: Vec<BridgeHit>,
    }

    #[derive(Deserialize)]
    struct BridgeHit {
        title: String,
        snippet: String,
        score: f64,
        source: String,
    }

    match response.json::<BridgeResponse>() {
        Ok(parsed) => parsed
            .results
            .into_iter()
            .map(|h| KbHit {
                title: h.title,
                snippet: h.snippet,
                score: h.score,
                source: h.source,
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Search artifacts by keyword AND query the KB for methodology context.
/// artifact_descriptions: plain-text descriptions from ParsedArtifact
pub fn combined_search(
    query: &str,
    artifact_descriptions: &[String],
    kb_limit: usize,
) -> CombinedSearchResult {
    let query_lower = query.to_lowercase();
    let artifact_hits: Vec<String> = artifact_descriptions
        .iter()
        .filter(|desc| desc.to_lowercase().contains(&query_lower))
        .take(20)
        .cloned()
        .collect();

    let kb_hits = query_kb_bridge(query, kb_limit);
    let kb_available = !kb_hits.is_empty();

    CombinedSearchResult {
        artifact_hits,
        kb_hits,
        kb_available,
    }
}

/// Ask the KB bridge for a plain-language artifact summary.
/// If the bridge or summarize endpoint is unavailable, fall back to a concise local summary.
pub fn summarize_artifacts_plain_language(artifact_descriptions: &[String]) -> String {
    if artifact_descriptions.is_empty() {
        return "No artifact descriptions were provided.".to_string();
    }

    let url = std::env::var("STRATA_KB_BRIDGE_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8090".to_string());
    let joined = artifact_descriptions
        .iter()
        .take(12)
        .map(|entry| entry.trim())
        .filter(|entry| !entry.is_empty())
        .collect::<Vec<_>>()
        .join("\n- ");

    if joined.is_empty() {
        return "Artifact descriptions were present but empty after normalization.".to_string();
    }

    let prompt = format!(
        "Summarize these forensic artifact descriptions in plain language for an examiner. Focus on what they indicate, avoid speculation, and keep it concise.\n- {}",
        joined
    );

    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
    {
        Ok(c) => c,
        Err(_) => return local_summary_fallback(artifact_descriptions),
    };

    let response = match client
        .post(format!("{}/summarize", url.trim_end_matches('/')))
        .json(&serde_json::json!({ "prompt": prompt }))
        .send()
    {
        Ok(r) => r,
        Err(_) => return local_summary_fallback(artifact_descriptions),
    };

    if !response.status().is_success() {
        return local_summary_fallback(artifact_descriptions);
    }

    #[derive(Deserialize)]
    struct SummarizeResponse {
        summary: Option<String>,
        content: Option<String>,
        text: Option<String>,
    }

    match response.json::<SummarizeResponse>() {
        Ok(parsed) => parsed
            .summary
            .or(parsed.content)
            .or(parsed.text)
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| local_summary_fallback(artifact_descriptions)),
        Err(_) => local_summary_fallback(artifact_descriptions),
    }
}

fn local_summary_fallback(artifact_descriptions: &[String]) -> String {
    let non_empty: Vec<&str> = artifact_descriptions
        .iter()
        .map(String::as_str)
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .collect();

    if non_empty.is_empty() {
        return "Artifact descriptions were present but contained no readable detail.".to_string();
    }

    let preview = non_empty
        .iter()
        .take(3)
        .map(|entry| {
            if entry.len() > 120 {
                format!("{}...", &entry[..120])
            } else {
                (*entry).to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" | ");

    format!(
        "Reviewed {} artifact description(s). Representative details: {}",
        non_empty.len(),
        preview
    )
}
