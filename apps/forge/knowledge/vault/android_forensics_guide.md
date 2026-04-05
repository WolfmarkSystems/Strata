# STRATA KNOWLEDGE: ANDROID FORENSIC ARTIFACTS (2024-2025)

This guide documents critical Android forensic artifacts for mobile device investigations.

---

## 📦 APPLICATION USAGE
- **Usage Stats**: `/data/system/usagestats/` - Records how long applications were in the foreground and how many times they were launched.
- **Package XML**: `/data/system/packages.xml` - Lists all installed apps, their permissions, and installation sources (e.g., sideloaded vs. Play Store).
- **Accounts**: `accounts.db` - Stores email addresses, social media handles, and authentication tokens for synced accounts.

---

## 💬 COMMUNICATIONS & MEDIA
- **SMS/MMS**: `mmssms.db` - SQLite database containing all text messages and delivery statuses.
- **Call Logs**: `contacts2.db` - Contains call history and saved contacts.
- **External Media**: `/sdcard/DCIM/` and `/sdcard/Pictures/` - Metadata in EXIF can reveal GPS coordinates and device info.

---

## 🚀 ANDROID 14/15: DEEP MASTERY (2025)
- **Digital Wellbeing (`dwbCommon.db`)**: Tracks actual time spent inside apps (dwell time), screen-on events, and notification counts. Crucial for establishing intent.
- **Sideloading Trace (`frosting.db`)**: Records which apps were installed outside the Play Store, including timestamps and original APK metadata.
- **Scoped Storage Impact**: Android 14+ restricts tool access to `/Android/data/`. Forensic imaging now requires specialized "Scoped Access" or Root for full app data recovery.
- **Photo Picker API**: Users can now select specific media without giving the app full storage permission; creates a new metadata trail in `media.db`.

---

## 📱 SYSTEM & SETTINGS
- **Settings Secure**: `settings_secure.db` - Stores device-wide settings, including ADB status, font scales, and accessibility services.
- **BT Config**: `/data/misc/bluedroid/bt_config.conf` - Records paired Bluetooth devices and discovery history.
- **Telephony**: `telephony.db` - Contains SIM card details, carriers, and signal history.
- **Battery Usage**: `turbo.db` - Detailed stats on which apps consumed power and when.

---

## 🏗️ ACQUISITION & SECURITY
- **ADB History**: `/data/misc/adb/adb_keys` - Shows which computers have authorized debugging access to the device.
- **Root Detection**: Checks for `su` binary or busybox in standard paths.
- **Physical vs. Logical**: Distinguishing between full disk images (physical) and API-supported extractions (logical).

**THIS KNOWLEDGE IS NOW PART OF STRATA'S CORE REASONING ENGINE.** 🛡️🦾
