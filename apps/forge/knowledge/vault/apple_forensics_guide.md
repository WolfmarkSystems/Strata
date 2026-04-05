# STRATA KNOWLEDGE: APPLE FORENSIC ARTIFACTS (2024-2025)

This guide documents critical forensic artifacts for macOS and iOS systems, essential for Strata's expanded mastery.

---

## 💻 macOS ARTIFACTS

### 🛡️ System Logs & Events
- **Apple Unified Log**: `/var/db/diagnostics/` - A massive, binary record of all system events. Requires `log show` or specialized parsers.
- **FSEvents**: `/.fseventsd/` - Tracks every file system change (create, delete, move). Crucial for timeline reconstruction.
- **System Logs**: `/var/log/system.log`, `install.log`, `appfirewall.log`.

### 📂 User Activity
- **Safari History**: `~/Library/Safari/History.db` (SQLite).
- **Keychain**: `~/Library/Keychains/` - Stores credentials and certificates.
- **Spotlight Index**: `/.Spotlight-V100/` - Metadata search index; reveals user search history and document access.
- **Shell History**: `~/.zsh_history`, `~/.bash_history`.
- **Quarantine Events**: `~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2` - Records all files downloaded from the web.

### ⚙️ Configuration & Metadata
- **PLIST Files**: System-wide configuration. Similar to Windows Registry.
- **DS_Store**: Hidden files in every folder indicating Finder access and custom views.
- **TCC Database**: `~/Library/Application Support/com.apple.TCC/TCC.db` - Records application permissions (Camera, Microphone, Full Disk Access).

---

## 📱 iOS ARTIFACTS

### 🧠 Intelligence & Usage
- **KnowledgeC**: `~/Library/CoreDuet/Knowledge/knowledgeC.db` - The "brain" of iOS. Records app usage, device lock/unlock, and even ambient light.
- **BIOME Data**: Modern replacement for some KnowledgeC functions; stores interaction and usage streams.
- **InteractionC**: `~/Library/CoreDuet/People/interactionC.db` - Tracks who the user communicates with most across apps.

### 💬 Communications
- **SMS/iMessage**: `~/Library/SMS/sms.db` (SQLite).
- **Call History**: `~/Library/CallHistoryDB/CallHistory.storedata`.
- **Address Book**: `~/Library/AddressBook/AddressBook.sqlitedb`.

### 📍 Location & Media
- **Cached Locations**: `~/Library/Caches/com.apple.routined/` (Usually 7-day retention).
- **Photos Database**: `~/Media/PhotoData/Photos.sqlite`.

---

## 🏗️ FILESYSTEM & SECURITY
- **APFS Snapshots**: Allows time-traveling through file system states.
- **FileVault 2**: Full disk encryption (XTS-AES-128).
- **Secure Enclave**: Handles biometric and cryptographic operations (T2/M1+ chips).

**THIS KNOWLEDGE IS NOW PART OF STRATA'S CORE REASONING ENGINE.** 🛡️🦾
