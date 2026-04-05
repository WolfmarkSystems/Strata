use crate::error::ForgeError;
use futures_util::StreamExt;
use reqwest::header::CONTENT_TYPE;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// LLM client for communicating with a local ollama instance.
#[derive(Debug, Clone)]
pub struct LlmClient {
    /// Base URL of the ollama API (default: http://localhost:11434).
    pub base_url: String,
    /// Model name to use (default: "llama3.2").
    pub model: String,
    /// Request timeout in seconds (default: 120).
    pub timeout_secs: u64,
    /// HTTP client (reusable connection pool).
    client: reqwest::Client,
}

/// Structured response from a non-streaming LLM request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmResponse {
    pub content: String,
    pub model: String,
    pub done: bool,
    pub total_tokens: Option<u32>,
}

/// A single streamed token delivered via callback.
#[derive(Debug, Clone, Serialize)]
pub struct StreamToken {
    pub token: String,
    pub done: bool,
}

/// Message in the conversation history sent to the LLM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

impl LlmClient {
    /// Create a new LLM client with the given configuration.
    pub fn new(base_url: &str, model: &str, timeout_secs: u64) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()
            .unwrap_or_default();

        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            model: model.to_string(),
            timeout_secs,
            client,
        }
    }

    /// Create a client with default settings (localhost:11434, llama3.2).
    pub fn default_local() -> Self {
        Self::new("http://localhost:11434", "llama3.2", 120)
    }

    /// Check if the ollama server is reachable and responding.
    pub async fn health_check(&self) -> bool {
        let url = format!("{}/api/tags", self.base_url);
        match self
            .client
            .get(&url)
            .timeout(Duration::from_secs(5))
            .send()
            .await
        {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        }
    }

    /// List available models on the ollama server.
    pub async fn list_models(&self) -> Result<Vec<String>, ForgeError> {
        let url = format!("{}/api/tags", self.base_url);
        let resp = self
            .client
            .get(&url)
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| ForgeError::llm_connection(format!("Failed to reach ollama: {}", e)))?;

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| ForgeError::llm_response(format!("Invalid JSON from ollama: {}", e)))?;

        let models = body
            .get("models")
            .and_then(|m| m.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|m| {
                        m.get("name")
                            .and_then(|n| n.as_str())
                            .map(|s| s.to_string())
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        Ok(models)
    }

    /// Send a non-streaming chat completion request.
    /// Returns the full response once the model finishes generating.
    pub async fn generate(
        &self,
        system_prompt: &str,
        messages: &[ChatMessage],
    ) -> Result<LlmResponse, ForgeError> {
        let url = format!("{}/v1/chat/completions", self.base_url);

        let mut all_messages = vec![ChatMessage {
            role: "system".to_string(),
            content: system_prompt.to_string(),
        }];
        all_messages.extend_from_slice(messages);

        let payload = serde_json::json!({
            "model": self.model,
            "messages": all_messages,
            "stream": false
        });

        let resp = self
            .client
            .post(&url)
            .header(CONTENT_TYPE, "application/json")
            .json(&payload)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    ForgeError::llm_timeout(format!(
                        "LLM request timed out after {}s",
                        self.timeout_secs
                    ))
                } else {
                    ForgeError::llm_connection(format!("Failed to reach ollama: {}", e))
                }
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(ForgeError::llm_response(format!(
                "Ollama returned {} — {}",
                status, body
            )));
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| ForgeError::llm_response(format!("Invalid JSON from ollama: {}", e)))?;

        let content = body["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or("")
            .to_string();

        let model = body["model"].as_str().unwrap_or(&self.model).to_string();

        let total_tokens = body["usage"]["total_tokens"].as_u64().map(|t| t as u32);

        Ok(LlmResponse {
            content,
            model,
            done: true,
            total_tokens,
        })
    }

    /// Send a streaming chat completion request.
    /// Calls `on_token` for each token as it arrives.
    /// Returns the full concatenated response when done.
    pub async fn generate_stream<F>(
        &self,
        system_prompt: &str,
        messages: &[ChatMessage],
        mut on_token: F,
    ) -> Result<String, ForgeError>
    where
        F: FnMut(StreamToken) -> Result<(), ForgeError>,
    {
        let url = format!("{}/v1/chat/completions", self.base_url);

        let mut all_messages = vec![ChatMessage {
            role: "system".to_string(),
            content: system_prompt.to_string(),
        }];
        all_messages.extend_from_slice(messages);

        let payload = serde_json::json!({
            "model": self.model,
            "messages": all_messages,
            "stream": true
        });

        let resp = self
            .client
            .post(&url)
            .header(CONTENT_TYPE, "application/json")
            .json(&payload)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    ForgeError::llm_timeout(format!(
                        "LLM request timed out after {}s",
                        self.timeout_secs
                    ))
                } else {
                    ForgeError::llm_connection(format!("Failed to reach ollama: {}", e))
                }
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(ForgeError::llm_response(format!(
                "Ollama returned {} — {}",
                status, body
            )));
        }

        let mut stream = resp.bytes_stream();
        let mut full_output = String::new();
        let mut buffer = String::new();

        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result
                .map_err(|e| ForgeError::llm_response(format!("Stream read error: {}", e)))?;
            let text = String::from_utf8_lossy(&chunk);
            buffer.push_str(&text);

            // Process complete SSE lines from buffer
            while let Some(newline_pos) = buffer.find('\n') {
                let line = buffer[..newline_pos].to_string();
                buffer = buffer[newline_pos + 1..].to_string();

                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                if let Some(data) = line.strip_prefix("data: ") {
                    if data == "[DONE]" {
                        on_token(StreamToken {
                            token: String::new(),
                            done: true,
                        })?;
                        return Ok(full_output);
                    }

                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(data) {
                        if let Some(token) = val["choices"][0]["delta"]["content"].as_str() {
                            if !token.is_empty() {
                                full_output.push_str(token);
                                on_token(StreamToken {
                                    token: token.to_string(),
                                    done: false,
                                })?;
                            }
                        }
                    }
                }
            }
        }

        // Signal done if stream ended without [DONE]
        on_token(StreamToken {
            token: String::new(),
            done: true,
        })?;

        Ok(full_output)
    }
}
