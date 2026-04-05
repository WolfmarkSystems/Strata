# Strata Forensics — Product Brief

**Document Type:** Procurement Summary
**Audience:** Government Procurement Officers, Agency Evaluators, Legal Counsel
**Effective Date:** 2026-03-27

---

## What Is Strata Forensics?

Strata Forensics is a professional-grade digital forensics platform built for government, law enforcement, and national security environments. It processes digital evidence containers, extracts artifacts, builds timelines, and generates court-ready reports — all entirely on the examiner's local workstation with no cloud dependency and no data leaving the machine.

## The Problem

Digital forensic examiners face growing evidence volumes, increasingly complex storage formats, and strict chain-of-custody requirements — all while operating under CJIS Security Policy and courtroom scrutiny. Most modern forensic tools introduce cloud services, telemetry, or external AI that create data sovereignty concerns for classified and sensitive investigations. Examiners need tools that are powerful, auditable, and provably local.

## Key Capabilities

- **Evidence Processing** — Opens and analyzes RAW/DD disk images, EnCase (E01) containers, and native directory sources with full filesystem enumeration
- **NTFS Deep Analysis** — Complete MFT parsing, USN Journal extraction, deleted file recovery, and attribute-level inspection
- **Multi-Filesystem Support** — NTFS, FAT32/exFAT, and ext4 with additional formats under development
- **Timeline Generation** — Automated artifact-based event reconstruction with timestamp normalization, date range filtering, and source path correlation
- **File Carving** — Signature-based recovery from unallocated space and slack space with confidence scoring across 50+ file types
- **Hash Verification** — MD5, SHA-1, and SHA-256 computation with NSRL (National Software Reference Library) integration and custom hashset support
- **Memory Acquisition** — Live RAM capture on Windows with dump parsing and process/DLL/network extraction
- **Court-Ready Reporting** — Professional HTML reports, JSONL timeline exports, and complete case bundles with hash chain-of-custody verification
- **Plugin Architecture** — Extensible parser system for agency-specific artifact types

## Local-Only Intelligent Reference System

Strata includes an on-device Intelligent Reference System (Forge) that assists examiners with methodology research and artifact interpretation — without any external network connection.

**What it does:**
- Searches a curated knowledge base of forensic methodology documents using natural language queries
- Returns source-cited passages that examiners can independently verify
- Provides plain-language summaries of examiner-selected artifact descriptions (advisory only)
- Logs every interaction in a complete audit trail before any operation executes

**What it does not do:**
- Connect to any external server, API, or cloud service
- Access evidence data without explicit examiner action
- Learn from or retain examiner queries between sessions
- Automatically insert any output into evidence records or reports
- Make forensic conclusions or determinations

The on-device model runs entirely on local hardware. Model weights are static, hash-verified at startup, and never modified by examiner input.

## Deployment Model

- **Fully local** — All processing, analysis, and on-device AI inference runs on the examiner's workstation
- **Air-gap compatible** — Functions identically with no network connection; suitable for classified environments
- **No cloud dependency** — No external services, telemetry, usage reporting, or callbacks of any kind
- **No persistent learning** — The local AI model does not learn from or retain examiner data

## Compliance Alignment

- **CJIS Security Policy** — Data sovereignty, audit logging, access control, and encryption at rest alignment documented with verification procedures
- **Federal Procurement** — No foreign service dependencies, air-gap deployable, complete audit trail, documented capability boundaries
- **Chain of Custody** — Hash-verified evidence integrity from ingest through reporting
- **Court Readiness** — Examiners can truthfully testify that all AI interactions are logged, all output was reviewed, and no data left the workstation

## Evaluation and Contact

To request an evaluation copy, technical demonstration, or additional procurement documentation:

- **Technical Evaluation Guide** — Available in this procurement package
- **Compliance Matrix** — CJIS and federal procurement alignment reference included
- **Contact:** [Evaluation contact placeholder — insert agency-appropriate contact information]

---

*Strata Forensics is developed and maintained by the Strata team. All capabilities described in this document are verified against the current release using the included Technical Evaluation Guide.*
