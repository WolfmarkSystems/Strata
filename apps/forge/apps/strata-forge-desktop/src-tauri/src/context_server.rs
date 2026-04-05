use crate::context::ForgeContext;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// A stored context with expiration. Context field used when query endpoint is wired.
#[allow(dead_code)]
struct StoredContext {
    context: ForgeContext,
    created: Instant,
}

/// Shared context store.
type ContextStore = Arc<Mutex<HashMap<String, StoredContext>>>;

/// Response for context submission.
#[derive(Serialize)]
struct ContextResponse {
    status: String,
    context_id: String,
}

/// Health response.
#[derive(Serialize)]
struct HealthResponse {
    status: String,
    version: String,
}

/// Error response.
#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

/// Query request from Tree (reserved for future streaming query endpoint).
#[derive(Deserialize)]
#[allow(dead_code)]
struct QueryRequest {
    query: String,
    context_id: Option<String>,
}

/// Query response to Tree (reserved for future streaming query endpoint).
#[derive(Serialize)]
#[allow(dead_code)]
struct QueryResponse {
    response: String,
    done: bool,
}

const CONTEXT_TTL: Duration = Duration::from_secs(3600); // 1 hour
const MAX_BODY_SIZE: usize = 1024 * 1024; // 1 MB

/// Start the context server on the given port. Runs in a background thread.
/// Returns a handle that can be used to check if the server is alive.
pub fn start_context_server(port: u16) -> Result<(), String> {
    // Try binding; if port is taken, try port+1
    let listener = match TcpListener::bind(format!("127.0.0.1:{}", port)) {
        Ok(l) => {
            println!("[CONTEXT SERVER] Listening on 127.0.0.1:{}", port);
            l
        }
        Err(_) => {
            let alt = port + 1;
            println!("[CONTEXT SERVER] Port {} in use, trying {}", port, alt);
            TcpListener::bind(format!("127.0.0.1:{}", alt)).map_err(|e| {
                format!(
                    "Failed to bind context server on ports {} or {}: {}",
                    port, alt, e
                )
            })?
        }
    };

    let store: ContextStore = Arc::new(Mutex::new(HashMap::new()));

    // Spawn cleanup thread
    let cleanup_store = store.clone();
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(300));
        if let Ok(mut map) = cleanup_store.lock() {
            map.retain(|_, v| v.created.elapsed() < CONTEXT_TTL);
        }
    });

    // Accept connections
    thread::spawn(move || {
        // Set non-blocking with a short accept timeout would be ideal,
        // but for simplicity, just accept in a loop
        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    let store = store.clone();
                    thread::spawn(move || {
                        if let Err(e) = handle_request(&mut stream, &store) {
                            eprintln!("[CONTEXT SERVER] Request error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("[CONTEXT SERVER] Accept error: {}", e);
                }
            }
        }
    });

    Ok(())
}

fn handle_request(stream: &mut std::net::TcpStream, store: &ContextStore) -> Result<(), String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;

    let mut reader = BufReader::new(stream.try_clone().map_err(|e| e.to_string())?);

    // Read request line
    let mut request_line = String::new();
    reader
        .read_line(&mut request_line)
        .map_err(|e| format!("Failed to read request: {}", e))?;

    let parts: Vec<&str> = request_line.trim().split(' ').collect();
    if parts.len() < 2 {
        return send_response(
            stream,
            400,
            &ErrorResponse {
                error: "Bad request".to_string(),
            },
        );
    }

    let method = parts[0];
    let path = parts[1];

    // Read headers
    let mut content_length: usize = 0;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).map_err(|e| e.to_string())?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        if let Some(val) = trimmed.strip_prefix("Content-Length:") {
            content_length = val.trim().parse().unwrap_or(0);
        }
        if let Some(val) = trimmed.strip_prefix("content-length:") {
            content_length = val.trim().parse().unwrap_or(0);
        }
    }

    // Read body
    let body = if content_length > 0 && content_length <= MAX_BODY_SIZE {
        let mut buf = vec![0u8; content_length];
        reader.read_exact(&mut buf).map_err(|e| e.to_string())?;
        String::from_utf8_lossy(&buf).to_string()
    } else {
        String::new()
    };

    // Route
    match (method, path) {
        ("GET", "/health") => {
            let resp = HealthResponse {
                status: "ok".to_string(),
                version: "0.1.0".to_string(),
            };
            send_response(stream, 200, &resp)
        }
        ("POST", "/api/context") => match serde_json::from_str::<ForgeContext>(&body) {
            Ok(ctx) => {
                let id = simple_uuid();
                if let Ok(mut map) = store.lock() {
                    map.insert(
                        id.clone(),
                        StoredContext {
                            context: ctx,
                            created: Instant::now(),
                        },
                    );
                }
                let resp = ContextResponse {
                    status: "ok".to_string(),
                    context_id: id,
                };
                send_response(stream, 200, &resp)
            }
            Err(e) => send_response(
                stream,
                400,
                &ErrorResponse {
                    error: format!("Invalid JSON: {}", e),
                },
            ),
        },
        ("GET", "/api/context") => {
            // List active context IDs
            let ids: Vec<String> = if let Ok(map) = store.lock() {
                map.keys().cloned().collect()
            } else {
                Vec::new()
            };
            send_response(stream, 200, &ids)
        }
        ("OPTIONS", _) => {
            // CORS preflight
            send_cors_preflight(stream)
        }
        _ => send_response(
            stream,
            404,
            &ErrorResponse {
                error: format!("Not found: {} {}", method, path),
            },
        ),
    }
}

fn send_response<T: Serialize>(
    stream: &mut std::net::TcpStream,
    status: u16,
    body: &T,
) -> Result<(), String> {
    let json = serde_json::to_string(body).unwrap_or_else(|_| "{}".to_string());
    let status_text = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "Unknown",
    };

    let response = format!(
        "HTTP/1.1 {} {}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
         Access-Control-Allow-Headers: Content-Type\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        status,
        status_text,
        json.len(),
        json
    );

    stream
        .write_all(response.as_bytes())
        .map_err(|e| format!("Failed to write response: {}", e))?;
    stream.flush().map_err(|e| e.to_string())?;
    Ok(())
}

fn send_cors_preflight(stream: &mut std::net::TcpStream) -> Result<(), String> {
    let response = "HTTP/1.1 204 No Content\r\n\
        Access-Control-Allow-Origin: *\r\n\
        Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
        Access-Control-Allow-Headers: Content-Type\r\n\
        Content-Length: 0\r\n\
        Connection: close\r\n\
        \r\n";
    stream
        .write_all(response.as_bytes())
        .map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;
    Ok(())
}

fn simple_uuid() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{:032x}", ts)
}
