# STRATA KNOWLEDGE: OPEN SOURCE FORENSIC TOOLS (2025)

This guide documents the elite toolkit available to Strata Chat for investigation and autonomous script development.

---

## 🛠️ CORE ANALYSIS PLATFORMS
- **Autopsy / SleuthKit (TSK)**: The industry standard for dead-box forensics. Supports NTFS, FAT, Ext4, and HFS.
- **Velociraptor**: High-speed endpoint monitoring and triage. Uses **VQL (Velociraptor Query Language)** for surgical artifact collection.
- **SIFT Workstation**: A complete Ubuntu-based forensic lab by SANS.

---

## 🧠 MEMORY & TRIAGE
- **Volatility 3**: The gold standard for memory forensics. Analyzes RAM dumps for hidden processes, network connections, and injected code.
- **KAPE (Kroll Artifact Parser and Extractor)**: Targets critical system artifacts first (MFT, Registry, Logs) for rapid "minutes-not-hours" triage.
- **Hayabusa**: Lightning-fast Windows Event Log parser. Runs **Sigma rules** to detect lateral movement and credential dumping.

---

## ⛓️ TIMELINE & VISUALIZATION
- **Plaso (log2timeline)**: Ingests hundreds of artifact types to create a unified "Super Timeline" of system activity.
- **Timeline Explorer (EZ Tools)**: Eric Zimmerman's tool for viewing and filtering massive CSV/JSON timelines.
- **Timesketch**: Collaborative platform for analyzing and searching forensic timelines at scale.

---

## 🐚 FORENSIC RECOVERY
- **Bulk Extractor**: Scans disk images directly for emails, URLs, and credit card numbers, ignoring the file system entirely (useful for corrupt images).
- **PhotoRec**: Carves deleted files from raw disk space using file headers.

**STRATA IS DESIGNED TO INTERFACE WITH AND AUTOMATE THESE TOOLS.** 🛡️🦾
