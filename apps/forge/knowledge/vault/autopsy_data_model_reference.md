# STRATA KNOWLEDGE: AUTOPSY & SLEUTHKIT DATA MODEL

This guide documents the internal data models of Autopsy and The Sleuth Kit (TSK), providing the logic for case management, the "Blackboard" communication system, and the SQLite schema.

---

## 🏗️ TSK DATA MODEL (org.sleuthkit.datamodel)
TSK provides a hierarchical view of forensic evidence:
1. **Device**: The physical or logical disk.
2. **Volume System**: Partition tables (GPT/MBR).
3. **Volume**: Individual partitions.
4. **File System**: NTFS, FAT, Ext4, HFS+, etc.
5. **File**: Metadata (MFT/Inode) and Content.

---

## 📓 THE BLACKBOARD SYSTEM
The Blackboard is Autopsy’s central database for storing "Artifacts" and "Attributes."
- **Blackboard Artifact**: A specific "finding" (e.g., `TSK_WEB_BOOKMARK`).
- **Blackboard Attribute**: A value associated with an artifact (e.g., `TSK_URL`, `TSK_DATETIME`).

### Key Artifact Types:
- `TSK_RECENT_OBJECT`: Recently accessed files/folders.
- `TSK_INSTALLED_PROG`: List of software found on the system.
- `TSK_KEYWORD_HIT`: Results from indexed search.
- `TSK_ACCOUNT`: Web, email, or social accounts.

---

## 🗄️ SQLITE SCHEMA (V1.5)
The underlying database (usually `autopsy.db`) contains several critical tables:
- **`tsk_objects`**: Parent-child relationships for every item in the case.
- **`tsk_files`**: Metadata for every file (name, size, timestamps, MD5).
- **`blackboard_artifacts`**: Links artifacts to the files they were found in.
- **`blackboard_attributes`**: The actual data values for those artifacts.

---

## 🛠️ THE SLEUTHKIT FRAMEWORK INTERNALS
- **`SleuthkitCase` class**: The main entry point for querying the database.
- **`FileManager`**: Provides methods to extract file content or stream it.
- **`IngestModule`**: The interface for creating automated analysis plugins (Java or Python).

---

## 🔬 ADVANCED: TSK IMPLEMENTATION NOTES (SKINs)
TSK handles file system complexity by mapping everything to generic structures:
- **`TSK_FS_INFO`**: Information about the file system (block size, etc.).
- **`TSK_FS_FILE`**: A single file/directory object.
- **`TSK_FS_ATTR`**: Data attributes (handles NTFS Alternate Data Streams).

**STRATA IS NOW EXPERT IN AUTOPSY & SLEUTHKIT INTERNALS.** 🦾🧠🔬
