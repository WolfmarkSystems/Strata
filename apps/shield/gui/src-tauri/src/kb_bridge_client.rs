use reqwest::blocking::Client;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::time::Duration;

const DEFAULT_KB_BRIDGE_URL: &str = "http://127.0.0.1:8090";

#[derive(Debug)]
pub enum KbBridgeError {
    InvalidBaseUrl(String),
    Http(String),
    Protocol(String),
}

impl std::fmt::Display for KbBridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidBaseUrl(message) => write!(f, "Invalid KB bridge URL: {}", message),
            Self::Http(message) => write!(f, "KB bridge request failed: {}", message),
            Self::Protocol(message) => write!(f, "KB bridge protocol error: {}", message),
        }
    }
}

impl std::error::Error for KbBridgeError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct KbSearchHit {
    pub source: String,
    pub path: String,
    pub title: String,
    pub score: f64,
    pub line_start: usize,
    pub line_end: usize,
    pub snippet: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct KbSearchResponse {
    pub query: String,
    pub results: Vec<KbSearchHit>,
    pub indexed_documents: usize,
    pub embedding_backend: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct KbBridgeHealth {
    pub status: String,
    pub vault_documents: usize,
    pub suite_documents: usize,
    pub indexed_documents: usize,
    pub embedding_backend: String,
    pub suite_root: Option<String>,
}

#[derive(Debug, Clone)]
pub struct KbBridgeClient {
    base_url: Url,
    http: Client,
}

impl KbBridgeClient {
    pub fn from_env() -> Result<Self, KbBridgeError> {
        let base = std::env::var("STRATA_KB_BRIDGE_URL")
            .unwrap_or_else(|_| DEFAULT_KB_BRIDGE_URL.to_string());
        Self::new(&base)
    }

    pub fn new(base_url: &str) -> Result<Self, KbBridgeError> {
        let parsed =
            Url::parse(base_url).map_err(|err| KbBridgeError::InvalidBaseUrl(err.to_string()))?;
        let http = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|err| KbBridgeError::Http(err.to_string()))?;
        Ok(Self {
            base_url: parsed,
            http,
        })
    }

    pub fn health(&self) -> Result<KbBridgeHealth, KbBridgeError> {
        let url = self.endpoint("health")?;
        let response = self
            .http
            .get(url)
            .send()
            .map_err(|err| KbBridgeError::Http(err.to_string()))?;

        if !response.status().is_success() {
            return Err(KbBridgeError::Protocol(format!(
                "health endpoint returned status {}",
                response.status()
            )));
        }

        response
            .json::<KbBridgeHealth>()
            .map_err(|err| KbBridgeError::Protocol(err.to_string()))
    }

    pub fn search(&self, query: &str, limit: usize) -> Result<KbSearchResponse, KbBridgeError> {
        let url = self.endpoint("search")?;
        let response = self
            .http
            .post(url)
            .json(&serde_json::json!({
                "query": query,
                "limit": limit.max(1),
            }))
            .send()
            .map_err(|err| KbBridgeError::Http(err.to_string()))?;

        if !response.status().is_success() {
            return Err(KbBridgeError::Protocol(format!(
                "search endpoint returned status {}",
                response.status()
            )));
        }

        response
            .json::<KbSearchResponse>()
            .map_err(|err| KbBridgeError::Protocol(err.to_string()))
    }

    fn endpoint(&self, path: &str) -> Result<Url, KbBridgeError> {
        self.base_url
            .join(path)
            .map_err(|err| KbBridgeError::InvalidBaseUrl(err.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    fn spawn_test_server(response_body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let addr = listener.local_addr().expect("listener addr");

        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buffer = [0u8; 4096];
                let _ = stream.read(&mut buffer);
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    response_body.len(),
                    response_body
                );
                let _ = stream.write_all(reply.as_bytes());
                let _ = stream.flush();
            }
        });

        format!("http://{}", addr)
    }

    #[test]
    fn health_response_is_parsed() {
        let url = spawn_test_server(
            r#"{"status":"ok","vault_documents":10,"suite_documents":3,"indexed_documents":13,"embedding_backend":"regex-token","suite_root":"d:/forensic-suite"}"#,
        );
        let client = KbBridgeClient::new(&url).expect("client");
        let health = client.health().expect("health response");
        assert_eq!(health.status, "ok");
        assert_eq!(health.suite_documents, 3);
        assert_eq!(health.indexed_documents, 13);
    }

    #[test]
    fn search_response_is_parsed() {
        let url = spawn_test_server(
            r#"{"query":"NTFS parser","results":[{"source":"suite","path":"docs/parser-contract.md","title":"parser contract","score":9.2,"line_start":10,"line_end":14,"snippet":"NTFS parser contract"}],"indexed_documents":42,"embedding_backend":"regex-token"}"#,
        );
        let client = KbBridgeClient::new(&url).expect("client");
        let response = client.search("NTFS parser", 5).expect("search response");
        assert_eq!(response.query, "NTFS parser");
        assert_eq!(response.results.len(), 1);
        assert_eq!(response.results[0].path, "docs/parser-contract.md");
    }

    #[test]
    #[ignore = "requires a running KB bridge on 127.0.0.1:8090"]
    fn live_query_for_ntfs_parser() {
        let client = KbBridgeClient::from_env().expect("client");
        let response = client
            .search("NTFS parser", 5)
            .expect("live search response");
        assert!(
            !response.results.is_empty(),
            "expected at least one search result for NTFS parser"
        );
    }
}
