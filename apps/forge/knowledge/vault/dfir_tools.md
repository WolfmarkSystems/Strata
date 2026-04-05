# DFIR Tool Development Resources

## Memory Forensics

### Volatility 3
- **GitHub**: https://github.com/volatilityfoundation/volatility3
- **Documentation**: https://volatility3.readthedocs.io/
- Python-based memory forensics framework

### Rekall
- **GitHub**: https://github.com/google/rekall
- Live memory analysis

## Disk Forensics

### Plaso (log2timeline)
- **GitHub**: https://github.com/log2timeline/plaso
- Timeline generation tool

### The Sleuth Kit
- **GitHub**: https://github.com/sleuthkit/sleuthkit
- Disk imaging and analysis

## Network Forensics

### Zeek
- **Official**: https://zeek.org/
- Network security monitor

### Suricata
- **Official**: https://suricata.io/
- IDS/IPS

## Malware Analysis

### CAPE Sandbox
- **GitHub**: https://github.com/kevoreilly/CAPEv2
- Malware sandbox

### YARA
- **Official**: https://virustotal.github.io/yara/
- Pattern matching for malware

## Log Analysis

### SIGMA
- **GitHub**: https://github.com/SigmaHQ/sigma
- Generic signature format for logs

### Chainsaw
- **GitHub**: https://github.com/WithSecureLabs/chainsaw
- Windows event log analysis

## Windows Forensics

### Windows Registry Parsing
- **python-winreg**: Built-in module
- **winreg** crate for Rust

### Event Log Analysis
- **evtx** (Python): EVTX parsing
- **chainsaw**: Rapid event log hunting

## File Parsing Libraries

### Rust
- `nom`: Parser combinators
- `binread`: Binary reading
- `x509-parser`: Certificate parsing
- `pe`: PE file parsing
- `gzip`, `zstd`: Decompression

### Python
- `pytsk3`: The Sleuth Kit Python bindings
- `pyewf`: Expert Witness format
- `construct`: Binary parsing

## Useful Commands

### Memory Acquisition
```bash
# Windows
winpmem_mini_x64.exe memory.raw

# Linux
LiME -o memdump.raw
```

### Disk Imaging
```bash
# Raw format
dd if=/dev/sda of=image.raw

# E01 format
ewfacquire image
```

### Timeline Analysis
```bash
log2timeline.py plaso.dump image.raw
psort.py plaso.dump -o L2tcsv timeline.csv
```

## Key Artifacts

| Artifact | Location | Tool |
|----------|----------|------|
| MFT | \$MFT | mft_parser |
| Registry | Various hive files | regipy |
| Event Logs | Windows/System32/winevt/logs |chainsaw |
| Browser History | User profiles | browsinghistoryview |
| Prefetch | Windows/Prefetch | pecmd |

## Chain of Custody

Always document:
1. Tool name and version
2. Execution timestamp (UTC)
3. Operator username
4. Hostname
5. Input file hash (SHA256)
6. Output file hash (SHA256)

Example JSON output:
```json
{
  "tool": "artifact_collector",
  "version": "1.0.0",
  "timestamp": "2025-01-01T00:00:00Z",
  "hostname": "FORENSIC-WORKSTATION",
  "operator": "analyst",
  "input_hash": "sha256:...",
  "output_hash": "sha256:...",
  "artifacts": [...]
}
```
