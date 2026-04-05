# DFIR Tool Development Best Practices

## Security-First Principles

### 1. Hostile Input Assumptions
- NEVER trust file paths, filenames, or data from untrusted sources
- Validate all inputs before processing
- Use allowlists instead of denylists where possible
- Sanitize filenames and paths to prevent path traversal attacks

### 2. Safe Parsing
- Use safe parsing libraries instead of manual string manipulation
- Handle malformed files gracefully - don't panic
- Implement proper error handling for corrupt/partial files
- Consider using `nom`, `binread`, or similar parsing crates

### 3. Memory Safety
- Prefer Rust for memory-safe parsing
- When interfacing with C libraries, wrap in unsafe with minimal scope
- Always check for integer overflow/underflow
- Use checked arithmetic operations

### 4. Deterministic Outputs
- Generate reproducible results for forensic reproducibility
- Avoid non-deterministic sorting without explicit seed
- Log timestamps in UTC with timezone info
- Output hashes/hex consistently

## DFIR Tool Patterns in Rust

### File Parsing Example Structure
```rust
use std::fs::File;
use std::io::{Read, BufReader, Result};

pub struct ForensicArtifact {
    pub timestamp: Option<DateTime<Utc>>,
    pub source_path: String,
    pub data: Vec<u8>,
}

impl ForensicArtifact {
    pub fn from_file(path: &Path) -> Result<Self> {
        // Validate path exists and is readable
        let path = pathcanonicalize(path)?;
        
        // Read file safely
        let mut file = File::open(path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;
        
        Ok(Self {
            timestamp: Some(Utc::now()),
            source_path: path.to_string_lossy().to_string(),
            data: buffer,
        })
    }
}
```

### Evidence Collection Pattern
```rust
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct EvidenceCollection {
    pub tool_name: String,
    pub tool_version: String,
    pub collection_time: DateTime<Utc>,
    pub machine_info: MachineInfo,
    pub artifacts: Vec<Artifact>,
}

#[derive(Serialize, Deserialize)]
pub struct MachineInfo {
    pub hostname: String,
    pub os: String,
    pub user: String,
}
```

## Recommended Crates for DFIR

### Parsing
- `nom` - Parser combinator library
- `binread` - Binary file parsing
- `x509-parser` - Certificate parsing
- `pe` - PE/COFF file parsing
- `gzip` - Gzip decompression

### Forensics
- `koffi` - FFI wrapper
- `windbg` - Windows debugging
- `libvmi` - Virtual Machine Introspection
- `clap` - CLI argument parsing
- `chrono` - Date/time handling
- `sha2`, `md5`, `blake3` - Hashing

### Logging & Output
- `tracing` - Structured logging
- `serde_json` - JSON output
- `csv` - CSV export

## Output Formats

### JSON for Machine Parsing
```json
{
  "tool": "artifact_collector",
  "version": "1.0.0",
  "timestamp": "2025-02-15T10:30:00Z",
  "hostname": "FORENSIC-WORKSTATION",
  "artifacts": [
    {
      "type": "registry",
      "path": "HKEY_LOCAL_MACHINE\\...",
      "data": {...}
    }
  ]
}
```

### Chain of Custody
Always include:
- Tool name and version
- Execution timestamp (UTC)
- Operator/user
- Hostname
- Input hash (if processing existing evidence)
- Output hash

## Testing DFIR Tools

### Fuzzing
- Use `cargo-fuzz` for fuzz testing
- Test with malformed/corrupt files
- Include sample evidence files in tests

### Test Data
- Create known-good test artifacts
- Include edge cases (empty files, max size, special characters)
- Use DFIR test images from training.dfirdiva.com

## Windows-Specific Considerations

### Registry
- Use `winreg` crate for registry access
- Handle missing keys gracefully
- Be aware of Wow6432Node paths

### Volatility
- Consider integration with Volatility 3
- Use proper memory acquisition indicators

### EDR/AV Interaction
- Handle cases where files are locked
- Consider Digital Signature status
- Be aware of AMSI bypass considerations (avoid)

## Anti-Patterns to Avoid

1. **Don't** use `unwrap()` on external data - use `?` or `match`
2. **Don't** log sensitive data (passwords, keys, PII)
3. **Don't** modify original evidence - always work on copies
4. **Don't** trust timestamps without verification
5. **Don't** implement own crypto - use established libraries
6. **Don't** skip error handling for "impossible" conditions
