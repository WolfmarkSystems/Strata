# Methodology

## Acquisition

1. Evidence image acquired using raw disk read
2. SHA256 hash computed for integrity verification
3. Write blocker used (if hardware available)

## Analysis

The following analysis methods were applied:

### Filesystem Analysis
- NTFS MFT parsing
- Deleted file recovery
- Timeline generation

### Content Analysis
- String extraction
- IOC scanning
- Carving for deleted files

### Hash Comparison
- Known file hash sets (NSRL)
- Malware hash databases

## Tools Used

- Forensic Suite v{{version}}
- X-Ways Forensics (comparison)
- Autopsy (comparison)
