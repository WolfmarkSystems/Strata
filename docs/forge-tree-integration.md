# Forge-Tree Integration Protocol

## Overview

Strata Forge exposes a local HTTP server on port 7842 (configurable) that
Strata Tree can POST evidence context to. This enables the "Open in Forge"
workflow: examiner selects an artifact in Tree, clicks a button, and Forge
receives the full context automatically.

Tree calls Forge. Forge never calls Tree.

## Endpoints

### Health Check

```
GET http://localhost:7842/health
```

Response:
```json
{"status": "ok", "version": "0.1.0"}
```

Use this to detect if Forge is running before POSTing context.

### Submit Context

```
POST http://localhost:7842/api/context
Content-Type: application/json

{
  "file_path": "C:\\Users\\Suspect\\Downloads\\mimikatz.exe",
  "file_hash_sha256": "abc123...",
  "file_size": 1234567,
  "file_category": "Executable",
  "registry_path": null,
  "command_line": null,
  "ioc_list": [],
  "case_name": "SMITH_2023_001",
  "timestamps": {
    "created": "2023-03-22T14:55:01Z",
    "modified": "2023-03-22T14:55:01Z",
    "accessed": "2023-03-22T15:00:00Z"
  }
}
```

Response:
```json
{"status": "ok", "context_id": "00000191abc123..."}
```

All fields are optional. Send whatever context Tree has available.
The context_id can be used for future query correlation.

### List Active Contexts

```
GET http://localhost:7842/api/context
```

Returns array of active context IDs. Contexts expire after 1 hour.

## Tree-Side Implementation

### Rust Example (using reqwest)

Tree already has reqwest as a dependency. Add this to the toolbar or
context menu handler:

```rust
use reqwest::blocking::Client;
use serde::Serialize;

#[derive(Serialize)]
struct ForgeContext {
    file_path: Option<String>,
    file_hash_sha256: Option<String>,
    file_size: Option<u64>,
    file_category: Option<String>,
    registry_path: Option<String>,
    command_line: Option<String>,
    ioc_list: Vec<String>,
    case_name: Option<String>,
    timestamps: Option<Timestamps>,
}

#[derive(Serialize)]
struct Timestamps {
    created: Option<String>,
    modified: Option<String>,
    accessed: Option<String>,
}

fn is_forge_running() -> bool {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .unwrap_or_default();
    client
        .get("http://localhost:7842/health")
        .send()
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

fn send_to_forge(ctx: &ForgeContext) -> Result<(), String> {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| format!("HTTP client error: {}", e))?;

    let resp = client
        .post("http://localhost:7842/api/context")
        .json(ctx)
        .send()
        .map_err(|e| format!("Failed to reach Forge: {}", e))?;

    if resp.status().is_success() {
        Ok(())
    } else {
        Err(format!("Forge returned {}", resp.status()))
    }
}
```

### "Open in Forge" Button Flow

1. Check if Forge is running: `GET /health`
2. If not running: launch `strata-forge.exe` (or show "Start Forge" message)
3. Wait up to 5 seconds for health check to succeed
4. POST the ForgeContext JSON to `/api/context`
5. Optionally focus the Forge window

### Building the ForgeContext from Tree State

```rust
fn build_forge_context(state: &AppState) -> ForgeContext {
    let file = state.selected_file();
    ForgeContext {
        file_path: file.map(|f| f.path.clone()),
        file_hash_sha256: file.and_then(|f| f.sha256.clone()),
        file_size: file.and_then(|f| f.size),
        file_category: file.and_then(|f| f.category.clone()),
        registry_path: None, // Set when in Registry view
        command_line: None,
        ioc_list: vec![],
        case_name: state.case.as_ref().map(|c| c.name.clone()),
        timestamps: file.map(|f| Timestamps {
            created: f.created_utc.clone(),
            modified: f.modified_utc.clone(),
            accessed: f.accessed_utc.clone(),
        }),
    }
}
```

## Port Configuration

Default port: 7842. Configurable in Forge settings
(`%APPDATA%\Strata\forge-settings.json`, key `context_server_port`).

If the port is occupied, Forge tries port+1 and logs a warning.

## CORS

The context server includes CORS headers permitting requests from any
origin. This allows browser-based tools to also send context if needed.

## Notes for Codex

- This document describes the contract. Do NOT modify Forge code.
- Tree's "Open in Forge" button belongs in the toolbar, next to HASH ALL.
- The ForgeContext struct in Tree should match the JSON schema above.
- reqwest blocking client is fine since this is called from a button handler.
- Log the Forge context submission to the audit trail: action="FORGE_CONTEXT_SENT".
