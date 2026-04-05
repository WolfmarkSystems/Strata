# STRATA KNOWLEDGE: WINDOWS FORENSIC ARTIFACTS (2024-2025)

This guide documents critical Windows forensic artifacts essential for Strata's mission-critical investigations.

---

## 🏛️ REGISTRY & EXECUTION
- **AmCache.hve**: `%SystemRoot%\AppCompat\Programs\Amcache.hve` - Records application execution, metadata, and SHA1 hashes.
- **ShimCache (AppCompatCache)**: SYSTEM hive - Tracks file presence and modification; used to identify potentially executed malware.
- **BAM / DAM**: SYSTEM hive - `\Services\bam\UserSettings` - Background Activity Moderator; records full path and last execution time of applications.
- **UserAssist**: NTUSER.dat - Records GUI applications launched by the user, including run counts and timestamps.
- **Prefetch**: `%SystemRoot%\Prefetch` - Performance artifacts that reveal application execution history and frequently accessed files.

---

## 📂 USER ACTIVITY & NAVIGATION
- **Jump Lists**: `%AppData%\Roaming\Microsoft\Windows\Recent\AutomaticDestinations` - Recently and frequently accessed files/folders.
- **ShellBags**: USRCLASS.dat - Records specific folder access and folder view preferences (even for deleted folders).
- **LNK Files**: Shortcut files created when a user opens a document; links behaviors to specific files.
- **$Recycle.Bin**: Stores original file paths and deletion timestamps.

---

## 🚀 WINDOWS 11: DEEP MASTERY (2025)
- **Windows Recall (AI Snapshots)**: 
    - **Database**: `%AppData%\Local\CoreAIPlatform.00\UKP\{GUID}\ukg.db` (SQLite).
    - **Images**: `%AppData%\Local\CoreAIPlatform.00\UKP\{GUID}\ImageStore\*` (JPEGs).
    - **Index**: `WindowCaptureTextIndex_content` - Contains OCR-recognized text from every screen the user has seen.
- **PCA App Launch Dictionary**: `C:\Windows\appcompat\pca\PcaAppLaunchDic.txt` - Plain text execution trace of programs launched via Explorer. Provides UTC timestamps and full paths.
- **SQLite Search Migration**: Windows Search now uses SQLite instead of ESE.
    - `Windows-gather.db`: Path reconstruction via ScopeID.
    - `Windows.db`: Metadata and SystemIndex_PropertyStore.
- **Notepad Persistence**: `%LocalAppData%\Packages\Microsoft.WindowsNotepad_8wekyb3d8bbwe\LocalState\TabState` - Stores unsaved tab contents and window states.

---

## 📊 SYSTEM PERFORMANCE & USAGE
- **SRUM (System Resource Usage Monitor)**: `%SystemRoot%\System32\sru\srudb.dat` - Tracks per-process network usage (data sent/received), battery, and CPU time. Crucial for data exfiltration analysis.
- **Event Logs (.evtx)**: 
    - **Security**: Logons (4624), Logoffs (4634), Process Creation (4688).
    - **System**: Services, Driver loads, USB connections.
    - **Microsoft-Windows-PowerShell/Operational**: Script block logging and command execution.

---

## 🔌 EXTERNAL DEVICES
- **USB Device Registry**: `SYSTEM\CurrentControlSet\Enum\USBSTOR` - Stores Vendor ID, Product ID, and Serial Numbers of connected devices.
- **SetupAPI Log**: `%SystemRoot%\inf\setupapi.dev.log` - Detailed timestamps of driver installations for new hardware/USB devices.

**THIS KNOWLEDGE IS NOW PART OF STRATA'S CORE REASONING ENGINE.** 🛡️🦾
