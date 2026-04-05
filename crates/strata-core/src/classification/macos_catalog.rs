use super::scalpel::{read_text_prefix, DEFAULT_TEXT_MAX_BYTES};
use plist::Value as PlistValue;
use rusqlite::types::ValueRef;
use rusqlite::Connection;
use serde_json::{Map, Value};
use std::env;
use std::fs;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

const APPLE_UNIX_EPOCH_OFFSET_SECS: i64 = 978_307_200;
const DEFAULT_DB_QUERY_LIMIT: usize = 3000;
const MAX_PLIST_DIRECTORY_SCAN_FILES: usize = 512;
const MAX_PLIST_TRAVERSAL_DEPTH: usize = 4;
const MAX_PLIST_SNIFF_BYTES: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacosCatalogFormat {
    Sqlite,
    TextLines,
}

#[derive(Debug, Clone)]
pub struct MacosCatalogSpec {
    pub key: String,
    pub description: String,
    pub format: MacosCatalogFormat,
    pub env_key: String,
    pub candidates: Vec<String>,
    pub query: String,
}

#[derive(Debug, Clone, Default)]
pub struct MacosCatalogRecord {
    pub artifact_key: String,
    pub source_path: String,
    pub timestamp_unix: Option<u64>,
    pub primary: String,
    pub secondary: Option<String>,
    pub detail: Option<String>,
    pub fields_json: Option<String>,
}

fn sqlite_spec(
    key: &str,
    description: &str,
    env_key: &str,
    candidates: Vec<String>,
    query: &str,
) -> MacosCatalogSpec {
    MacosCatalogSpec {
        key: key.to_string(),
        description: description.to_string(),
        format: MacosCatalogFormat::Sqlite,
        env_key: env_key.to_string(),
        candidates,
        query: query.to_string(),
    }
}

fn text_spec(
    key: &str,
    description: &str,
    env_key: &str,
    candidates: Vec<String>,
) -> MacosCatalogSpec {
    MacosCatalogSpec {
        key: key.to_string(),
        description: description.to_string(),
        format: MacosCatalogFormat::TextLines,
        env_key: env_key.to_string(),
        candidates,
        query: String::new(),
    }
}

fn s(value: &str) -> String {
    value.to_string()
}

pub fn macos_catalog_specs() -> Vec<MacosCatalogSpec> {
    let mut specs = vec![
        sqlite_spec(
            "macos.safari.history",
            "Safari browsing history entries",
            "FORENSIC_MACOS_SAFARI_HISTORY_DB",
            vec![
                s("{HOME}/Library/Safari/History.db"),
                s("artifacts/macos/safari/History.db"),
            ],
            "SELECT COALESCE(hi.url,''), COALESCE(hi.title,''), CAST(hv.visit_time AS REAL) AS ts, COALESCE(hi.visit_count,1) AS visit_count FROM history_visits hv JOIN history_items hi ON hi.id = hv.history_item ORDER BY hv.visit_time DESC LIMIT 3000",
        ),
        sqlite_spec(
            "macos.safari.downloads",
            "Safari download records",
            "FORENSIC_MACOS_SAFARI_HISTORY_DB",
            vec![
                s("{HOME}/Library/Safari/History.db"),
                s("artifacts/macos/safari/History.db"),
            ],
            "SELECT COALESCE(duc.url,''), COALESCE(d.path,''), CAST(d.download_entry_date AS REAL) AS ts FROM downloads d LEFT JOIN downloads_url_chains duc ON duc.id = d.id ORDER BY d.download_entry_date DESC LIMIT 3000",
        ),
        sqlite_spec(
            "macos.chrome.history",
            "Chrome history on macOS",
            "FORENSIC_MACOS_CHROME_HISTORY_DB",
            vec![
                s("{HOME}/Library/Application Support/Google/Chrome/Default/History"),
                s("artifacts/macos/chrome/History"),
            ],
            "SELECT COALESCE(url,''), COALESCE(title,''), CAST(last_visit_time AS REAL) AS ts, COALESCE(visit_count,1) AS visit_count FROM urls ORDER BY last_visit_time DESC LIMIT 3000",
        ),
        sqlite_spec(
            "macos.chrome.downloads",
            "Chrome downloads on macOS",
            "FORENSIC_MACOS_CHROME_HISTORY_DB",
            vec![
                s("{HOME}/Library/Application Support/Google/Chrome/Default/History"),
                s("artifacts/macos/chrome/History"),
            ],
            "SELECT COALESCE(current_path,''), COALESCE(tab_url,''), CAST(start_time AS REAL) AS ts, COALESCE(received_bytes,0) AS bytes FROM downloads ORDER BY start_time DESC LIMIT 3000",
        ),
        sqlite_spec(
            "macos.chrome.cookies",
            "Chrome cookie database on macOS",
            "FORENSIC_MACOS_CHROME_COOKIES_DB",
            vec![
                s("{HOME}/Library/Application Support/Google/Chrome/Default/Cookies"),
                s("artifacts/macos/chrome/Cookies"),
            ],
            "SELECT COALESCE(host_key,''), COALESCE(name,''), CAST(last_access_utc AS REAL) AS ts, COALESCE(value,'') FROM cookies ORDER BY last_access_utc DESC LIMIT 3000",
        ),
        sqlite_spec(
            "macos.chrome.logins",
            "Chrome Login Data entries",
            "FORENSIC_MACOS_CHROME_LOGIN_DB",
            vec![
                s("{HOME}/Library/Application Support/Google/Chrome/Default/Login Data"),
                s("artifacts/macos/chrome/Login Data"),
            ],
            "SELECT COALESCE(origin_url,''), COALESCE(username_value,''), CAST(date_last_used AS REAL) AS ts FROM logins ORDER BY date_last_used DESC LIMIT 3000",
        ),
        sqlite_spec(
            "macos.firefox.history",
            "Firefox places history",
            "FORENSIC_MACOS_FIREFOX_PLACES_DB",
            vec![
                s("{HOME}/Library/Application Support/Firefox/Profiles/default-release/places.sqlite"),
                s("artifacts/macos/firefox/places.sqlite"),
            ],
            "SELECT COALESCE(url,''), COALESCE(title,''), CAST(last_visit_date AS REAL) AS ts, COALESCE(visit_count,1) AS visit_count FROM moz_places ORDER BY last_visit_date DESC LIMIT 3000",
        ),
        sqlite_spec(
            "macos.firefox.downloads",
            "Firefox download traces",
            "FORENSIC_MACOS_FIREFOX_PLACES_DB",
            vec![
                s("{HOME}/Library/Application Support/Firefox/Profiles/default-release/places.sqlite"),
                s("artifacts/macos/firefox/places.sqlite"),
            ],
            "SELECT COALESCE(p.url,''), COALESCE(a.content,''), CAST(v.visit_date AS REAL) AS ts FROM moz_places p LEFT JOIN moz_annos a ON a.place_id = p.id LEFT JOIN moz_historyvisits v ON v.place_id = p.id WHERE a.content LIKE 'file:%' OR a.content LIKE '%/%' ORDER BY v.visit_date DESC LIMIT 3000",
        ),
        sqlite_spec(
            "macos.firefox.cookies",
            "Firefox cookie store",
            "FORENSIC_MACOS_FIREFOX_COOKIES_DB",
            vec![
                s("{HOME}/Library/Application Support/Firefox/Profiles/default-release/cookies.sqlite"),
                s("artifacts/macos/firefox/cookies.sqlite"),
            ],
            "SELECT COALESCE(host,''), COALESCE(name,''), CAST(lastAccessed AS REAL) AS ts, COALESCE(value,'') FROM moz_cookies ORDER BY lastAccessed DESC LIMIT 3000",
        ),
        sqlite_spec(
            "macos.firefox.formhistory",
            "Firefox form history entries",
            "FORENSIC_MACOS_FIREFOX_FORMHISTORY_DB",
            vec![
                s("{HOME}/Library/Application Support/Firefox/Profiles/default-release/formhistory.sqlite"),
                s("artifacts/macos/firefox/formhistory.sqlite"),
            ],
            "SELECT COALESCE(fieldname,''), COALESCE(value,''), CAST(lastUsed AS REAL) AS ts, COALESCE(timesUsed,0) AS times_used FROM moz_formhistory ORDER BY lastUsed DESC LIMIT 3000",
        ),
        sqlite_spec(
            "macos.brave.history",
            "Brave history on macOS",
            "FORENSIC_MACOS_BRAVE_HISTORY_DB",
            vec![
                s("{HOME}/Library/Application Support/BraveSoftware/Brave-Browser/Default/History"),
                s("artifacts/macos/brave/History"),
            ],
            "SELECT COALESCE(url,''), COALESCE(title,''), CAST(last_visit_time AS REAL) AS ts, COALESCE(visit_count,1) FROM urls ORDER BY last_visit_time DESC LIMIT 3000",
        ),
        sqlite_spec(
            "macos.edge.history",
            "Edge history on macOS",
            "FORENSIC_MACOS_EDGE_HISTORY_DB",
            vec![
                s("{HOME}/Library/Application Support/Microsoft Edge/Default/History"),
                s("artifacts/macos/edge/History"),
            ],
            "SELECT COALESCE(url,''), COALESCE(title,''), CAST(last_visit_time AS REAL) AS ts FROM urls ORDER BY last_visit_time DESC LIMIT 3000",
        ),
        sqlite_spec(
            "macos.opera.history",
            "Opera history on macOS",
            "FORENSIC_MACOS_OPERA_HISTORY_DB",
            vec![
                s("{HOME}/Library/Application Support/com.operasoftware.Opera/History"),
                s("artifacts/macos/opera/History"),
            ],
            "SELECT COALESCE(url,''), COALESCE(title,''), CAST(last_visit_time AS REAL) AS ts FROM urls ORDER BY last_visit_time DESC LIMIT 3000",
        ),
        sqlite_spec(
            "macos.tor.history",
            "Tor Browser history",
            "FORENSIC_MACOS_TOR_PLACES_DB",
            vec![
                s("{HOME}/Library/Application Support/TorBrowser-Data/Browser/profile.default/places.sqlite"),
                s("artifacts/macos/tor/places.sqlite"),
            ],
            "SELECT COALESCE(url,''), COALESCE(title,''), CAST(last_visit_date AS REAL) AS ts FROM moz_places ORDER BY last_visit_date DESC LIMIT 3000",
        ),
        sqlite_spec(
            "macos.quarantine.events",
            "LaunchServices quarantine event records",
            "FORENSIC_MACOS_QUARANTINE_DB",
            vec![
                s("{HOME}/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"),
                s("{HOME}/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2.db"),
                s("artifacts/macos/quarantine/QuarantineEventsV2.db"),
            ],
            "SELECT * FROM LSQuarantineEvent ORDER BY LSQuarantineTimeStamp DESC LIMIT 3000",
        ),
        sqlite_spec(
            "macos.tcc.access",
            "TCC privacy access database",
            "FORENSIC_MACOS_TCC_DB",
            vec![
                s("{HOME}/Library/Application Support/com.apple.TCC/TCC.db"),
                s("artifacts/macos/tcc/TCC.db"),
            ],
            "SELECT * FROM access ORDER BY last_modified DESC LIMIT 3000",
        ),
        sqlite_spec(
            "macos.messages.chat",
            "Messages chat transcripts",
            "FORENSIC_MACOS_MESSAGES_DB",
            vec![s("{HOME}/Library/Messages/chat.db"), s("artifacts/macos/messages/chat.db")],
            "SELECT * FROM message ORDER BY date DESC LIMIT 3000",
        ),
        sqlite_spec(
            "macos.messages.attachments",
            "Messages attachment records",
            "FORENSIC_MACOS_MESSAGES_DB",
            vec![s("{HOME}/Library/Messages/chat.db"), s("artifacts/macos/messages/chat.db")],
            "SELECT * FROM attachment ORDER BY ROWID DESC LIMIT 3000",
        ),
        sqlite_spec(
            "macos.callhistory.calls",
            "Call history store records",
            "FORENSIC_MACOS_CALLHISTORY_DB",
            vec![
                s("{HOME}/Library/Application Support/CallHistoryDB/CallHistory.storedata"),
                s("artifacts/macos/callhistory/CallHistory.storedata"),
            ],
            "SELECT * FROM ZCALLRECORD ORDER BY ZDATE DESC LIMIT 3000",
        ),
        sqlite_spec(
            "macos.notes.records",
            "Apple Notes records",
            "FORENSIC_MACOS_NOTES_DB",
            vec![
                s("{HOME}/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite"),
                s("artifacts/macos/notes/NoteStore.sqlite"),
            ],
            "SELECT * FROM ZICCLOUDSYNCINGOBJECT ORDER BY ZMODIFICATIONDATE DESC LIMIT 3000",
        ),
        sqlite_spec(
            "macos.calendar.events",
            "Calendar event records",
            "FORENSIC_MACOS_CALENDAR_DB",
            vec![s("{HOME}/Library/Calendars/Calendar Cache"), s("artifacts/macos/calendar/Calendar Cache")],
            "SELECT * FROM CalendarItem ORDER BY start_date DESC LIMIT 3000",
        ),
        sqlite_spec(
            "macos.contacts.people",
            "Contacts person records",
            "FORENSIC_MACOS_CONTACTS_DB",
            vec![
                s("{HOME}/Library/Application Support/AddressBook/AddressBook-v22.abcddb"),
                s("artifacts/macos/contacts/AddressBook-v22.abcddb"),
            ],
            "SELECT * FROM ZABCDRECORD ORDER BY ZMODIFICATIONDATE DESC LIMIT 3000",
        ),
        sqlite_spec(
            "macos.knowledgec.events",
            "knowledgeC event/activity records",
            "FORENSIC_MACOS_KNOWLEDGEC_DB",
            vec![
                s("{HOME}/Library/Application Support/Knowledge/knowledgeC.db"),
                s("artifacts/macos/knowledge/knowledgeC.db"),
            ],
            "SELECT * FROM ZOBJECT ORDER BY ZSTARTDATE DESC LIMIT 3000",
        ),
        sqlite_spec(
            "macos.mail.envelope_index",
            "Mail envelope index messages",
            "FORENSIC_MACOS_MAIL_DB",
            vec![
                s("{HOME}/Library/Mail/V10/MailData/Envelope Index"),
                s("artifacts/macos/mail/Envelope Index"),
            ],
            "SELECT * FROM messages ORDER BY date_sent DESC LIMIT 3000",
        ),
        sqlite_spec(
            "macos.quicklook.thumbnails",
            "QuickLook thumbnail cache index",
            "FORENSIC_MACOS_QUICKLOOK_DB",
            vec![
                s("{HOME}/Library/Containers/com.apple.QuickLook.thumbnailcache/Data/Library/Caches/com.apple.QuickLook.thumbnailcache/index.sqlite"),
                s("artifacts/macos/quicklook/index.sqlite"),
            ],
            "SELECT * FROM files ORDER BY last_hit_date DESC LIMIT 3000",
        ),
        text_spec(
            "macos.shell.zsh_history",
            "zsh shell history",
            "FORENSIC_MACOS_ZSH_HISTORY",
            vec![s("{HOME}/.zsh_history"), s("artifacts/macos/shell/.zsh_history")],
        ),
        text_spec(
            "macos.shell.bash_history",
            "bash shell history",
            "FORENSIC_MACOS_BASH_HISTORY",
            vec![s("{HOME}/.bash_history"), s("artifacts/macos/shell/.bash_history")],
        ),
        text_spec(
            "macos.shell.fish_history",
            "fish shell history",
            "FORENSIC_MACOS_FISH_HISTORY",
            vec![s("{HOME}/.local/share/fish/fish_history"), s("artifacts/macos/shell/fish_history")],
        ),
        text_spec(
            "macos.installhistory",
            "InstallHistory.plist software install records",
            "FORENSIC_MACOS_INSTALL_HISTORY",
            vec![s("/Library/Receipts/InstallHistory.plist"), s("artifacts/macos/system/InstallHistory.plist")],
        ),
        text_spec(
            "macos.wifi.known_networks",
            "Known Wi-Fi networks plist",
            "FORENSIC_MACOS_WIFI_KNOWN",
            vec![
                s("/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist"),
                s("artifacts/macos/network/airport.preferences.plist"),
            ],
        ),
        text_spec(
            "macos.bluetooth.paired_devices",
            "Bluetooth paired devices plist",
            "FORENSIC_MACOS_BLUETOOTH_PAIRED",
            vec![s("/Library/Preferences/com.apple.Bluetooth.plist"), s("artifacts/macos/network/Bluetooth.plist")],
        ),
        text_spec(
            "macos.network.interfaces",
            "Network interface plist",
            "FORENSIC_MACOS_NETWORK_INTERFACES",
            vec![
                s("/Library/Preferences/SystemConfiguration/NetworkInterfaces.plist"),
                s("artifacts/macos/network/NetworkInterfaces.plist"),
            ],
        ),
        text_spec(
            "macos.time_machine.history",
            "Time Machine backup history",
            "FORENSIC_MACOS_TIME_MACHINE",
            vec![s("/Library/Preferences/com.apple.TimeMachine.plist"), s("artifacts/macos/backup/TimeMachine.plist")],
        ),
        text_spec(
            "macos.system.version",
            "SystemVersion plist",
            "FORENSIC_MACOS_SYSTEM_VERSION",
            vec![s("/System/Library/CoreServices/SystemVersion.plist"), s("artifacts/macos/system/SystemVersion.plist")],
        ),
    ];

    const EXTENDED_TEXT_ARTIFACTS: &[(&str, &str)] = &[
        ("macos.safari.last_session", "Safari LastSession plist"),
        (
            "macos.safari.recently_closed",
            "Safari recently closed tabs/windows",
        ),
        ("macos.safari.cookies_binary", "Safari binary cookie store"),
        (
            "macos.browser.recent_tabs_cache",
            "Browser recent tabs session cache",
        ),
        ("macos.browser.top_sites", "Browser top sites cache"),
        ("macos.browser.favicons", "Browser favicon cache"),
        (
            "macos.browser.extensions",
            "Browser extension manifest cache",
        ),
        (
            "macos.browser.sessions",
            "Browser session persistence files",
        ),
        ("macos.browser.webdata", "Browser webdata database exports"),
        (
            "macos.browser.login_state",
            "Browser login/session metadata",
        ),
        (
            "macos.browser.permissions",
            "Browser permissions and grants",
        ),
        (
            "macos.browser.notifications",
            "Browser notification permission state",
        ),
        (
            "macos.browser.download_shelves",
            "Browser download shelf/cache",
        ),
        ("macos.browser.search_terms", "Browser search term history"),
        (
            "macos.browser.media_history",
            "Browser media playback history",
        ),
        ("macos.browser.autofill", "Browser autofill text cache"),
        ("macos.browser.bookmarks", "Browser bookmarks export"),
        ("macos.browser.cache_index", "Browser cache index"),
        (
            "macos.browser.network_actions",
            "Browser network action logs",
        ),
        (
            "macos.browser.hsts",
            "Browser HSTS / transport security state",
        ),
        ("macos.xprotect.diagnostics", "XProtect diagnostics logs"),
        ("macos.xprotect.remediator", "XProtect remediator logs"),
        (
            "macos.gatekeeper.assessments",
            "Gatekeeper assessment/cache data",
        ),
        (
            "macos.loginitems.backgrounditems",
            "Background items manager data",
        ),
        (
            "macos.loginitems.shared_file_list",
            "Shared file list login items",
        ),
        ("macos.launchagents.user", "User LaunchAgents plist files"),
        (
            "macos.launchagents.system",
            "System LaunchAgents plist files",
        ),
        (
            "macos.launchdaemons.system",
            "System LaunchDaemons plist files",
        ),
        ("macos.sudo.history", "Sudo command audit history"),
        ("macos.crashreports.user", "User crash reports"),
        ("macos.crashreports.system", "System crash reports"),
        ("macos.unifiedlog.extract", "Unified logging text export"),
        ("macos.fsevents.extract", "FSEvents textual export"),
        ("macos.asl.extract", "ASL log extraction"),
        (
            "macos.spotlight.shortcuts",
            "Spotlight shortcut and query hints",
        ),
        (
            "macos.spotlight.metadata_store",
            "Spotlight metadata store extraction",
        ),
        (
            "macos.spotlight.volume_config",
            "Spotlight per-volume config",
        ),
        ("macos.spotlight.search_queries", "Spotlight query history"),
        ("macos.recent_items", "Recent Items plist traces"),
        (
            "macos.finder.recent_folders",
            "Finder recent folders/preferences",
        ),
        ("macos.finder.sidebarlists", "Finder sidebarlists plist"),
        ("macos.finder.tags", "Finder tag metadata"),
        ("macos.finder.preferences", "Finder preference plist"),
        (
            "macos.finder.saved_searches",
            "Finder saved search descriptors",
        ),
        ("macos.finder.window_state", "Finder window state caches"),
        ("macos.finder.last_opened", "Finder last opened metadata"),
        (
            "macos.finder.favorite_servers",
            "Finder favorite server list",
        ),
        ("macos.finder.recents_sfl", "Finder recents SFL records"),
        ("macos.dock.persistent_apps", "Dock persistent app list"),
        ("macos.dock.recent_apps", "Dock recent app entries"),
        (
            "macos.saved_state.windows",
            "NSWindow saved state artifacts",
        ),
        ("macos.preview.recents", "Preview recents plist"),
        ("macos.office.mru", "Microsoft Office MRU plist/cache"),
        (
            "macos.office.autorecover",
            "Office AutoRecovery folder content",
        ),
        ("macos.vscode.recents", "VS Code storage/recent workspaces"),
        ("macos.terminal.saved_state", "Terminal saved state"),
        (
            "macos.iterm2.shell_integration",
            "iTerm2 command history/logs",
        ),
        ("macos.ssh.known_hosts", "SSH known_hosts entries"),
        ("macos.ssh.config", "SSH config file entries"),
        ("macos.print.recent_jobs", "Recent print job traces"),
        ("macos.network.dhcp_leases", "DHCP lease files"),
        ("macos.network.vpn", "VPN configurations"),
        ("macos.network.proxies", "Proxy config entries"),
        (
            "macos.network.firewall_rules",
            "Firewall and pf config traces",
        ),
        ("macos.network.route_table", "Route table exports"),
        ("macos.network.resolver", "Resolver configuration"),
        (
            "macos.network.services",
            "Network service set configuration",
        ),
        ("macos.network.airdrop", "AirDrop interaction traces"),
        ("macos.network.airplay", "AirPlay target history"),
        ("macos.network.hotspot", "Personal hotspot state/history"),
        (
            "macos.network.icloud_private_relay",
            "iCloud private relay state",
        ),
        (
            "macos.network.location_services",
            "Location services network context",
        ),
        ("macos.network.airport_logs", "Airport/Wi-Fi logs"),
        (
            "macos.network.packet_filter_logs",
            "Packet filter textual logs",
        ),
        (
            "macos.network.socketfilterfw",
            "Socket filter firewall state",
        ),
        (
            "macos.icloud.drive_metadata",
            "iCloud Drive metadata traces",
        ),
        ("macos.onedrive.logs", "OneDrive logs/config on macOS"),
        ("macos.dropbox.logs", "Dropbox logs/config on macOS"),
        ("macos.googledrive.logs", "Google Drive sync logs on macOS"),
        (
            "macos.whatsapp.desktop_cache",
            "WhatsApp Desktop local cache",
        ),
        ("macos.slack.cache", "Slack local cache artifacts"),
        ("macos.teams.cache", "Teams local cache artifacts"),
        ("macos.discord.cache", "Discord local cache artifacts"),
        ("macos.telegram.cache", "Telegram local cache artifacts"),
        ("macos.signal.cache", "Signal Desktop local cache"),
        ("macos.zoom.logs", "Zoom app logs and traces"),
        ("macos.webex.logs", "Webex logs and traces"),
        ("macos.skype.logs", "Skype local logs"),
        ("macos.browser_profiles", "Browser profile index"),
        ("macos.mail.rules", "Mail rules plist content"),
        ("macos.mail.signature", "Mail signatures"),
        ("macos.mail.accounts", "Mail account settings"),
        ("macos.mail.downloads", "Mail attachment download traces"),
        ("macos.mail.recent_recipients", "Mail recent recipients"),
        (
            "macos.mail.vacation_rules",
            "Mail vacation/auto-response rules",
        ),
        (
            "macos.accounts.internet_accounts",
            "Internet Accounts metadata export",
        ),
        (
            "macos.accounts.keychain_metadata",
            "Keychain metadata export",
        ),
        ("macos.keychain.access_groups", "Keychain access groups"),
        ("macos.keychain.lock_state", "Keychain lock/unlock traces"),
        (
            "macos.security.authorizationdb",
            "Authorization database export",
        ),
        ("macos.filevault.status", "FileVault status outputs"),
        (
            "macos.launchservices.secure",
            "LaunchServices secure plist records",
        ),
        ("macos.lsregister.dump", "LSRegister dump text"),
        ("macos.app_translocation", "App translocation traces/logs"),
        (
            "macos.user.loginwindow",
            "LoginWindow prefs and recent users",
        ),
        ("macos.power.sleepwake", "Sleep/wake and power event logs"),
        ("macos.power.battery_history", "Battery history traces"),
        ("macos.power.thermal", "Thermal and power event traces"),
        ("macos.preferences.global", "Global preferences plist"),
        (
            "macos.preferences.security",
            "Security preference pane state",
        ),
        ("macos.preferences.privacy", "Privacy preference pane state"),
        (
            "macos.preferences.notifications",
            "Notification settings traces",
        ),
        ("macos.preferences.keyboard", "Keyboard preference traces"),
        ("macos.preferences.trackpad", "Trackpad preference traces"),
        ("macos.preferences.mouse", "Mouse preference traces"),
        ("macos.preferences.display", "Display preference traces"),
        ("macos.preferences.bluetooth", "Bluetooth preference traces"),
        ("macos.preferences.sharing", "Sharing preference traces"),
        (
            "macos.preferences.softwareupdate",
            "Software update preference traces",
        ),
        (
            "macos.preferences.parentalcontrols",
            "Parental control traces",
        ),
        ("macos.preferences.siri", "Siri preference traces"),
        ("macos.preferences.spotlight", "Spotlight preference traces"),
        ("macos.preferences.timezone", "Time zone preference traces"),
        (
            "macos.preferences.language",
            "Language and locale preferences",
        ),
        (
            "macos.preferences.accessibility",
            "Accessibility preference traces",
        ),
        (
            "macos.preferences.notifications_summary",
            "Notification summary traces",
        ),
    ];

    let mut additional_specs = vec![
        sqlite_spec(
            "macos.notes",
            "Notes application database",
            "FORENSIC_MACOS_NOTES",
            vec![
                s("{HOME}/Library/Notes/Notes.sqlite"),
                s("artifacts/macos/notes/Notes.sqlite"),
            ],
            "SELECT ZNOTEBODY, ZCREATIONDATE, ZMODIFICATIONDATE FROM ZNOTE ORDER BY ZMODIFICATIONDATE DESC LIMIT 3000",
        ),
        sqlite_spec(
            "macos.calendar",
            "Calendar events database",
            "FORENSIC_MACOS_CALENDAR",
            vec![
                s("{HOME}/Library/Calendars/Calendar.sqlite"),
                s("artifacts/macos/calendar/Calendar.sqlite"),
            ],
            "SELECT ZTITLE, ZSTARTDATE, ZENDDATE, ZLOCATION FROM ZCALENDARITEM ORDER BY ZSTARTDATE DESC LIMIT 3000",
        ),
        sqlite_spec(
            "macos.contacts",
            "Address Book contacts",
            "FORENSIC_MACOS_CONTACTS",
            vec![
                s("{HOME}/Library/Application Support/AddressBook/AddressBook.sqlitedb"),
                s("artifacts/macos/contacts/AddressBook.sqlitedb"),
            ],
            "SELECT ZFIRSTNAME, ZLASTNAME, ZEMAILADDRESSES, ZPHONENUMBERS FROM ZABCDRECORD ORDER BY ZMODIFICATIONDATE DESC LIMIT 3000",
        ),
        sqlite_spec(
            "macos.reminders",
            "Reminders database",
            "FORENSIC_MACOS_REMINDERS",
            vec![
                s("{HOME}/Library/Reminders/Reminders.sqlite"),
                s("artifacts/macos/reminders/Reminders.sqlite"),
            ],
            "SELECT ZTITLE, ZDUEDATE, ZCOMPLETEDDATE, ZPRIORITY FROM ZREMINDER ORDER BY ZCREATIONDATE DESC LIMIT 3000",
        ),
        sqlite_spec(
            "macos.photos.metadata",
            "Photos library metadata",
            "FORENSIC_MACOS_PHOTOS",
            vec![
                s("{HOME}/Pictures/Photos Library.photoslibrary/database/Photos.sqlite"),
                s("artifacts/macos/photos/Photos.sqlite"),
            ],
            "SELECT ZFILENAME, ZDATECREATED, ZIMPORTDATE FROM ZGENERICASSET ORDER BY ZDATECREATED DESC LIMIT 3000",
        ),
        sqlite_spec(
            "macos.keychain.items",
            "Keychain items",
            "FORENSIC_MACOS_KEYCHAIN",
            vec![
                s("{HOME}/Library/Keychains/login.keychain-db"),
                s("System/Library/Keychains/System.keychain"),
                s("artifacts/macos/keychain/keychain.db"),
            ],
            "SELECT ZPLLABEL, ZPLACCOUNT, ZPASSWORDDATE, ZLASTMODIFIEDDATE FROM ZGENERICPASSWORD ORDER BY ZLASTMODIFIEDDATE DESC LIMIT 3000",
        ),
        sqlite_spec(
            "macos.safari.tabs",
            "Safari open tabs",
            "FORENSIC_MACOS_SAFARI_TABS",
            vec![
                s("{HOME}/Library/Safari/Bookmarks.plist"),
                s("artifacts/macos/safari/Bookmarks.plist"),
            ],
            "SELECT ZTITLE, ZURL, ZDATEVISITED FROM ZSAFARITABLEROW ORDER BY ZDATEVISITED DESC LIMIT 3000",
        ),
        sqlite_spec(
            "macos.fseventsd",
            "Filesystem events log",
            "FORENSIC_MACOS_FSEVENTSD",
            vec![
                s("/private/var/log/fs_event_log"),
                s("artifacts/macos/fsevents/fsevents.log"),
            ],
            "SELECT * FROM fsevents LIMIT 3000",
        ),
        sqlite_spec(
            "macos.unifiedlogs",
            "Unified logging system logs",
            "FORENSIC_MACOS_UNIFIED_LOGS",
            vec![
                s("{HOME}/Library/Logs/DiagnosticReports"),
                s("/var/db/diagnostics/Library/Logs"),
                s("artifacts/macos/logs/unified"),
            ],
            "SELECT timestamp, process, subsystem, category, message FROM log_entries LIMIT 3000",
        ),
    ];

    for spec in additional_specs.drain(..) {
        if !specs.iter().any(|s| s.key == spec.key) {
            specs.push(spec);
        }
    }

    for (key, description) in EXTENDED_TEXT_ARTIFACTS {
        if specs.iter().any(|s| s.key == *key) {
            continue;
        }
        let env_key = format!("FORENSIC_{}", key.to_ascii_uppercase().replace('.', "_"));
        let fallback = format!("artifacts/macos/catalog/{}.txt", key.replace('.', "_"));
        specs.push(text_spec(key, description, &env_key, vec![fallback]));
    }

    const EXPANDED_CATEGORIES: &[&str] = &[
        "apfs",
        "hfsplus",
        "launchservices",
        "xpc",
        "mds",
        "quicklook",
        "icloud",
        "keychain",
        "securityd",
        "trustd",
        "powerd",
        "coreduet",
        "coreservices",
        "distnoted",
        "cfnetwork",
        "nsurlsessiond",
        "appstore",
        "softwareupdate",
        "locationd",
        "analyticsd",
    ];

    const EXPANDED_SUFFIXES: &[(&str, &str)] = &[
        ("events", "events"),
        ("history", "history"),
        ("config", "configuration"),
        ("cache", "cache"),
        ("state", "state"),
        ("diagnostics", "diagnostics"),
    ];

    for category in EXPANDED_CATEGORIES {
        for (suffix, label) in EXPANDED_SUFFIXES {
            let key = format!("macos.expanded.{}.{}", category, suffix);
            if specs.iter().any(|s| s.key == key) {
                continue;
            }
            let description = format!(
                "Expanded macOS {} {} parser",
                category.replace('_', " "),
                label
            );
            let env_key = format!("FORENSIC_{}", key.to_ascii_uppercase().replace('.', "_"));
            let fallback = format!(
                "artifacts/macos/catalog_expanded/{}/{}.txt",
                category, suffix
            );
            specs.push(text_spec(&key, &description, &env_key, vec![fallback]));
        }
    }

    specs
}

pub fn list_macos_catalog_keys() -> Vec<String> {
    macos_catalog_specs().into_iter().map(|s| s.key).collect()
}

pub fn parse_macos_catalog_artifact(key: &str) -> Vec<MacosCatalogRecord> {
    let Some(spec) = macos_catalog_specs().into_iter().find(|s| s.key == key) else {
        return Vec::new();
    };
    parse_spec(&spec)
}

pub fn parse_all_macos_catalog_artifacts() -> Vec<MacosCatalogRecord> {
    let mut out = Vec::new();
    for spec in macos_catalog_specs() {
        out.extend(parse_spec(&spec));
    }
    out
}

fn parse_spec(spec: &MacosCatalogSpec) -> Vec<MacosCatalogRecord> {
    let mut out = Vec::new();
    let paths = resolve_candidate_paths(spec);
    for path in paths {
        match spec.format {
            MacosCatalogFormat::Sqlite => out.extend(parse_sqlite_artifact(spec, &path)),
            MacosCatalogFormat::TextLines => out.extend(parse_text_artifact(spec, &path)),
        }
    }
    out
}

fn parse_sqlite_artifact(spec: &MacosCatalogSpec, path: &Path) -> Vec<MacosCatalogRecord> {
    if spec.query.trim().is_empty() {
        return Vec::new();
    }
    let Ok(conn) = Connection::open(path) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    let query = ensure_limit(&spec.query, DEFAULT_DB_QUERY_LIMIT);
    let Ok(mut stmt) = conn.prepare(&query) else {
        return out;
    };
    let column_names: Vec<String> = stmt.column_names().iter().map(|v| v.to_string()).collect();
    let rows = stmt.query_map([], |row| {
        let mut fields = Map::new();
        for (idx, name) in column_names.iter().enumerate() {
            let value = row
                .get_ref(idx)
                .ok()
                .map(value_ref_to_json)
                .unwrap_or(Value::Null);
            fields.insert(name.clone(), value);
        }
        Ok(fields)
    });

    let Ok(iter) = rows else {
        return out;
    };

    for fields in iter.flatten() {
        let timestamp_unix = infer_timestamp_from_fields(&fields);
        let primary = infer_primary(&fields);
        if primary.is_empty() {
            continue;
        }
        out.push(MacosCatalogRecord {
            artifact_key: spec.key.clone(),
            source_path: path.display().to_string(),
            timestamp_unix,
            primary: primary.clone(),
            secondary: infer_secondary(&fields, &primary),
            detail: Some(summarize_fields(&fields)),
            fields_json: serde_json::to_string(&fields).ok(),
        });
    }

    out
}

fn parse_text_artifact(spec: &MacosCatalogSpec, path: &Path) -> Vec<MacosCatalogRecord> {
    if path.is_dir() {
        return parse_directory_artifact(spec, path);
    }

    if should_try_plist_for_path(spec, path) {
        let plist_rows = parse_plist_artifact(spec, path);
        if !plist_rows.is_empty() {
            return plist_rows;
        }
    }

    let Ok(content) = read_text_prefix(path, DEFAULT_TEXT_MAX_BYTES) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in content.lines().take(DEFAULT_DB_QUERY_LIMIT) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with('#') && trimmed.chars().skip(1).all(|c| c.is_ascii_digit()) {
            continue;
        }
        let timestamp_unix = parse_line_timestamp(trimmed);
        out.push(MacosCatalogRecord {
            artifact_key: spec.key.clone(),
            source_path: path.display().to_string(),
            timestamp_unix,
            primary: clean_shell_line(trimmed),
            secondary: None,
            detail: None,
            fields_json: None,
        });
    }
    out
}

fn parse_directory_artifact(spec: &MacosCatalogSpec, dir: &Path) -> Vec<MacosCatalogRecord> {
    let mut out = Vec::new();

    // For plist-heavy artifacts (LaunchAgents, preferences, etc.) parse structured plist files.
    if is_plist_focused_spec(spec) {
        let plist_files = collect_plist_files(dir, MAX_PLIST_DIRECTORY_SCAN_FILES);
        for file in plist_files {
            out.extend(parse_plist_artifact(spec, &file));
            if out.len() >= DEFAULT_DB_QUERY_LIMIT {
                out.truncate(DEFAULT_DB_QUERY_LIMIT);
                return out;
            }
        }
    }

    // Fallback for non-plist directories: capture shallow file listing.
    if out.is_empty() {
        let mut listed = 0usize;
        let mut stack: Vec<(PathBuf, usize)> = vec![(dir.to_path_buf(), 0)];
        while let Some((current, depth)) = stack.pop() {
            let Ok(entries) = strata_fs::read_dir(&current) else {
                continue;
            };
            let mut paths: Vec<PathBuf> = entries.flatten().map(|entry| entry.path()).collect();
            paths.sort_by(|a, b| a.to_string_lossy().cmp(&b.to_string_lossy()));
            for path in paths {
                if path.is_dir() {
                    if depth < 1 {
                        stack.push((path, depth + 1));
                    }
                    continue;
                }
                listed += 1;
                out.push(MacosCatalogRecord {
                    artifact_key: spec.key.clone(),
                    source_path: dir.display().to_string(),
                    timestamp_unix: None,
                    primary: path.display().to_string(),
                    secondary: None,
                    detail: Some("directory_listing".to_string()),
                    fields_json: None,
                });
                if listed >= DEFAULT_DB_QUERY_LIMIT {
                    return out;
                }
            }
        }
    }

    out
}

fn should_try_plist_for_path(spec: &MacosCatalogSpec, path: &Path) -> bool {
    is_plist_focused_spec(spec) || is_plist_file(path)
}

fn is_plist_focused_spec(spec: &MacosCatalogSpec) -> bool {
    let key = spec.key.to_ascii_lowercase();
    let desc = spec.description.to_ascii_lowercase();
    key.contains("plist")
        || key.contains("launchagents")
        || key.contains("launchdaemons")
        || key.contains("preferences")
        || key.contains("launchservices")
        || key.contains("loginitems")
        || desc.contains("plist")
}

fn is_plist_file(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    matches!(
        ext.as_str(),
        "plist" | "sfl" | "sfl2" | "btm" | "bookmark" | "webloc"
    )
}

fn collect_plist_files(root: &Path, max_files: usize) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack: Vec<(PathBuf, usize)> = vec![(root.to_path_buf(), 0)];

    while let Some((current, depth)) = stack.pop() {
        if out.len() >= max_files {
            break;
        }
        let Ok(entries) = strata_fs::read_dir(&current) else {
            continue;
        };
        let mut paths: Vec<PathBuf> = entries.flatten().map(|entry| entry.path()).collect();
        paths.sort_by(|a, b| a.to_string_lossy().cmp(&b.to_string_lossy()));
        for path in paths {
            if out.len() >= max_files {
                break;
            }
            if path.is_dir() {
                if depth < MAX_PLIST_TRAVERSAL_DEPTH {
                    stack.push((path, depth + 1));
                }
                continue;
            }
            if is_plist_file(&path) || looks_like_plist_file(&path) {
                out.push(path);
            }
        }
    }

    out
}

fn parse_plist_artifact(spec: &MacosCatalogSpec, path: &Path) -> Vec<MacosCatalogRecord> {
    let Ok(root) = PlistValue::from_file(path) else {
        return Vec::new();
    };
    let root_json = serde_json::to_value(&root).unwrap_or(Value::Null);
    let mut out = build_semantic_plist_records(spec, path, &root_json);
    let remaining = DEFAULT_DB_QUERY_LIMIT.saturating_sub(out.len());
    if remaining == 0 {
        return out;
    }

    let mut flattened: Vec<(String, Value)> = Vec::new();

    // First try JSON conversion (fast path for regular plist value shapes).
    if !root_json.is_null() {
        flatten_json_leaves_limited("", &root_json, &mut flattened, 0, remaining);
    }

    // Fallback for plist variants that do not serialize cleanly (for example UID-heavy bplist).
    if flattened.is_empty() {
        flatten_plist_leaves("", &root, &mut flattened, 0, remaining);
    }

    if flattened.is_empty() {
        if out.is_empty() {
            return vec![MacosCatalogRecord {
                artifact_key: spec.key.clone(),
                source_path: path.display().to_string(),
                timestamp_unix: None,
                primary: format!("plist:{}", path.display()),
                secondary: None,
                detail: Some("plist_empty".to_string()),
                fields_json: None,
            }];
        }
        return out;
    }

    for (key_path, value) in flattened.into_iter() {
        let primary_value = value_to_short_string(&value);
        if primary_value.is_empty() {
            continue;
        }

        let timestamp_unix = parse_timestamp_value(&value);
        let mut fields = Map::new();
        fields.insert("key_path".to_string(), Value::String(key_path.clone()));
        fields.insert("value".to_string(), value.clone());

        out.push(MacosCatalogRecord {
            artifact_key: spec.key.clone(),
            source_path: path.display().to_string(),
            timestamp_unix,
            primary: format!("{}={}", key_path, primary_value),
            secondary: None,
            detail: Some("plist_leaf".to_string()),
            fields_json: serde_json::to_string(&fields).ok(),
        });
    }

    if out.is_empty() {
        let root_json = if root_json.is_null() {
            Value::String(format!("{:?}", root))
        } else {
            root_json
        };
        out.push(MacosCatalogRecord {
            artifact_key: spec.key.clone(),
            source_path: path.display().to_string(),
            timestamp_unix: infer_timestamp_from_value(&root_json),
            primary: format!("plist:{}", path.display()),
            secondary: None,
            detail: Some("plist_root".to_string()),
            fields_json: serde_json::to_string(&root_json).ok(),
        });
    }

    out
}

fn build_semantic_plist_records(
    spec: &MacosCatalogSpec,
    path: &Path,
    root_json: &Value,
) -> Vec<MacosCatalogRecord> {
    let mut out = Vec::new();
    let fields = root_json.as_object();
    let key_lc = spec.key.to_ascii_lowercase();

    if key_lc.contains("launchagent")
        || key_lc.contains("launchdaemon")
        || key_lc.contains("launchservices")
    {
        if let Some(fields) = fields {
            if let Some(record) = build_launchd_semantic_record(spec, path, fields, root_json) {
                out.push(record);
            }
        }
    }

    if key_lc.contains("preferences")
        || key_lc.contains("finder")
        || key_lc.contains("recent_items")
        || key_lc.contains("sidebar")
    {
        if let Some(fields) = fields {
            if let Some(record) = build_preferences_semantic_record(spec, path, fields, root_json) {
                out.push(record);
            }
        }
    }

    if key_lc.contains("loginitems") {
        if let Some(record) = build_loginitems_semantic_record(spec, path, root_json) {
            out.push(record);
        }
    }

    if key_lc.contains("finder") && key_lc.contains("sidebar") {
        if let Some(record) = build_finder_sidebar_semantic_record(spec, path, root_json) {
            out.push(record);
        }
    }

    if key_lc.contains("recent_items")
        || key_lc.contains("recent_folders")
        || key_lc.contains("recents_sfl")
    {
        if let Some(record) = build_recent_items_semantic_record(spec, path, root_json) {
            out.push(record);
        }
    }

    if key_lc.contains("launchservices") {
        if let Some(record) = build_launchservices_semantic_record(spec, path, root_json) {
            out.push(record);
        }
    }

    if key_lc.contains("dock.") {
        if let Some(record) = build_dock_semantic_record(spec, path, root_json) {
            out.push(record);
        }
    }

    if key_lc.contains("preview.recents") {
        if let Some(record) = build_preview_recents_semantic_record(spec, path, root_json) {
            out.push(record);
        }
    }

    if key_lc.contains("office.mru") {
        if let Some(record) = build_office_mru_semantic_record(spec, path, root_json) {
            out.push(record);
        }
    }

    if key_lc.contains("mail.rules") {
        if let Some(record) = build_mail_rules_semantic_record(spec, path, root_json) {
            out.push(record);
        }
    }

    if key_lc.contains("mail.accounts") {
        if let Some(record) = build_mail_accounts_semantic_record(spec, path, root_json) {
            out.push(record);
        }
    }

    if key_lc.contains("user.loginwindow") {
        if let Some(record) = build_loginwindow_semantic_record(spec, path, root_json) {
            out.push(record);
        }
    }

    if key_lc.contains("network.vpn")
        || key_lc.contains("network.proxies")
        || key_lc.contains("network.services")
    {
        if let Some(record) = build_network_preferences_semantic_record(spec, path, root_json) {
            out.push(record);
        }
    }

    if key_lc.contains("system.version") {
        if let Some(fields) = fields {
            if let Some(record) =
                build_system_version_semantic_record(spec, path, fields, root_json)
            {
                out.push(record);
            }
        }
    }

    if key_lc.contains("time_machine.history") {
        if let Some(record) = build_time_machine_semantic_record(spec, path, root_json) {
            out.push(record);
        }
    }

    if key_lc.contains("network.interfaces") {
        if let Some(record) = build_network_interfaces_semantic_record(spec, path, root_json) {
            out.push(record);
        }
    }

    if key_lc.contains("wifi.known_networks") {
        if let Some(record) = build_wifi_known_networks_semantic_record(spec, path, root_json) {
            out.push(record);
        }
    }

    if key_lc.contains("installhistory") {
        if let Some(record) = build_installhistory_semantic_record(spec, path, root_json) {
            out.push(record);
        }
    }

    if key_lc.contains("bluetooth.paired_devices") {
        if let Some(record) = build_bluetooth_paired_semantic_record(spec, path, root_json) {
            out.push(record);
        }
    }

    if key_lc.contains("network.airdrop") {
        if let Some(record) = build_airdrop_semantic_record(spec, path, root_json) {
            out.push(record);
        }
    }

    if key_lc.contains("network.airplay") {
        if let Some(record) = build_airplay_semantic_record(spec, path, root_json) {
            out.push(record);
        }
    }

    if key_lc.contains("network.hotspot") {
        if let Some(record) = build_hotspot_semantic_record(spec, path, root_json) {
            out.push(record);
        }
    }

    if key_lc.contains("network.icloud_private_relay") {
        if let Some(record) = build_private_relay_semantic_record(spec, path, root_json) {
            out.push(record);
        }
    }

    if key_lc.contains("network.location_services") {
        if let Some(record) = build_location_services_semantic_record(spec, path, root_json) {
            out.push(record);
        }
    }

    if key_lc.contains("print.recent_jobs") {
        if let Some(record) = build_print_recent_jobs_semantic_record(spec, path, root_json) {
            out.push(record);
        }
    }

    if key_lc.contains("finder.tags") {
        if let Some(record) = build_finder_tags_semantic_record(spec, path, root_json) {
            out.push(record);
        }
    }

    if key_lc.contains("saved_state.windows") {
        if let Some(record) = build_saved_state_windows_semantic_record(spec, path, root_json) {
            out.push(record);
        }
    }

    out
}

fn build_launchd_semantic_record(
    spec: &MacosCatalogSpec,
    path: &Path,
    fields: &Map<String, Value>,
    root_json: &Value,
) -> Option<MacosCatalogRecord> {
    let label = get_field_string_ci(fields, "label");
    let program = get_field_string_ci(fields, "program");
    let program_args = get_program_arguments(fields);
    let run_at_load = get_field_bool_ci(fields, "runatload");
    let disabled = get_field_bool_ci(fields, "disabled");
    let user_name = get_field_string_ci(fields, "username");
    let keep_alive = fields
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("keepalive"))
        .map(|(_, v)| value_to_short_string(v))
        .filter(|v| !v.is_empty());

    if label.is_none()
        && program.is_none()
        && program_args.is_none()
        && run_at_load.is_none()
        && disabled.is_none()
        && user_name.is_none()
        && keep_alive.is_none()
    {
        return None;
    }

    let mut semantic = Map::new();
    if let Some(v) = label.clone() {
        semantic.insert("label".to_string(), Value::String(v));
    }
    if let Some(v) = program.clone() {
        semantic.insert("program".to_string(), Value::String(v));
    }
    if let Some(v) = program_args.clone() {
        semantic.insert("program_arguments".to_string(), Value::String(v));
    }
    if let Some(v) = run_at_load {
        semantic.insert("run_at_load".to_string(), Value::Bool(v));
    }
    if let Some(v) = disabled {
        semantic.insert("disabled".to_string(), Value::Bool(v));
    }
    if let Some(v) = user_name.clone() {
        semantic.insert("user_name".to_string(), Value::String(v));
    }
    if let Some(v) = keep_alive.clone() {
        semantic.insert("keep_alive".to_string(), Value::String(v));
    }

    let primary = label
        .clone()
        .map(|v| format!("launchd.label={}", v))
        .or_else(|| program.clone().map(|v| format!("launchd.program={}", v)))
        .or_else(|| program_args.clone().map(|v| format!("launchd.args={}", v)))
        .unwrap_or_else(|| format!("launchd.source={}", path.display()));

    let secondary = program
        .or(program_args)
        .or(user_name)
        .filter(|v| !primary.contains(v));

    Some(MacosCatalogRecord {
        artifact_key: spec.key.clone(),
        source_path: path.display().to_string(),
        timestamp_unix: infer_timestamp_from_value(root_json),
        primary,
        secondary,
        detail: Some("plist_semantic_launchd".to_string()),
        fields_json: serde_json::to_string(&semantic).ok(),
    })
}

fn build_preferences_semantic_record(
    spec: &MacosCatalogSpec,
    path: &Path,
    fields: &Map<String, Value>,
    root_json: &Value,
) -> Option<MacosCatalogRecord> {
    let domain = path
        .file_name()
        .and_then(|s| s.to_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());

    let candidate_keys = [
        "AppleLocale",
        "AppleLanguages",
        "AppleICUForce24HourTime",
        "NSNavLastRootDirectory",
        "Country",
        "LastUpdateDate",
        "LastSelectedDatastore",
        "RecentItems",
        "ShowHardDrivesOnDesktop",
        "ShowExternalHardDrivesOnDesktop",
        "ShowRemovableMediaOnDesktop",
        "ShowMountedServersOnDesktop",
    ];

    let mut semantic = Map::new();
    for key in candidate_keys {
        if let Some(value) = get_field_case_insensitive(fields, key) {
            let rendered = value_to_short_string(value);
            if !rendered.is_empty() {
                semantic.insert(key.to_string(), Value::String(rendered));
            }
        }
    }

    if semantic.is_empty() {
        return None;
    }

    semantic.insert("domain".to_string(), Value::String(domain.clone()));
    let secondary = semantic
        .iter()
        .find(|(k, _)| k.as_str() != "domain")
        .and_then(|(k, v)| v.as_str().map(|s| format!("{}={}", k, s)));

    Some(MacosCatalogRecord {
        artifact_key: spec.key.clone(),
        source_path: path.display().to_string(),
        timestamp_unix: infer_timestamp_from_value(root_json),
        primary: format!("preferences.domain={}", domain),
        secondary,
        detail: Some("plist_semantic_preferences".to_string()),
        fields_json: serde_json::to_string(&semantic).ok(),
    })
}

fn build_loginitems_semantic_record(
    spec: &MacosCatalogSpec,
    path: &Path,
    root_json: &Value,
) -> Option<MacosCatalogRecord> {
    let names = collect_leaf_strings_by_key_tokens(
        root_json,
        &["name", "label", "title", "displayname"],
        24,
    );
    let paths =
        collect_leaf_strings_by_key_tokens(root_json, &["path", "url", "bookmark", "alias"], 24);
    let bundle_ids = collect_leaf_strings_by_key_tokens(
        root_json,
        &["bundleidentifier", "bundle_id", "identifier"],
        16,
    );

    if names.is_empty() && paths.is_empty() && bundle_ids.is_empty() {
        return None;
    }

    let mut semantic = Map::new();
    semantic.insert(
        "item_count".to_string(),
        Value::from(names.len().max(paths.len()).max(bundle_ids.len()) as u64),
    );
    if !names.is_empty() {
        semantic.insert(
            "sample_names".to_string(),
            Value::Array(names.iter().take(10).cloned().map(Value::String).collect()),
        );
    }
    if !paths.is_empty() {
        semantic.insert(
            "sample_paths".to_string(),
            Value::Array(paths.iter().take(10).cloned().map(Value::String).collect()),
        );
    }
    if !bundle_ids.is_empty() {
        semantic.insert(
            "sample_bundle_ids".to_string(),
            Value::Array(
                bundle_ids
                    .iter()
                    .take(10)
                    .cloned()
                    .map(Value::String)
                    .collect(),
            ),
        );
    }

    let primary = paths
        .first()
        .map(|v| format!("loginitems.path={}", v))
        .or_else(|| names.first().map(|v| format!("loginitems.name={}", v)))
        .or_else(|| {
            bundle_ids
                .first()
                .map(|v| format!("loginitems.bundle_id={}", v))
        })
        .unwrap_or_else(|| format!("loginitems.source={}", path.display()));

    let secondary = names
        .first()
        .filter(|v| !primary.contains(*v))
        .cloned()
        .or_else(|| paths.first().filter(|v| !primary.contains(*v)).cloned())
        .or_else(|| {
            bundle_ids
                .first()
                .filter(|v| !primary.contains(*v))
                .cloned()
        });

    Some(MacosCatalogRecord {
        artifact_key: spec.key.clone(),
        source_path: path.display().to_string(),
        timestamp_unix: infer_timestamp_from_value(root_json),
        primary,
        secondary,
        detail: Some("plist_semantic_loginitems".to_string()),
        fields_json: serde_json::to_string(&semantic).ok(),
    })
}

fn build_finder_sidebar_semantic_record(
    spec: &MacosCatalogSpec,
    path: &Path,
    root_json: &Value,
) -> Option<MacosCatalogRecord> {
    let items = collect_leaf_strings_by_key_tokens(
        root_json,
        &[
            "sidebar", "favorite", "volume", "server", "name", "path", "url",
        ],
        40,
    );
    if items.is_empty() {
        return None;
    }

    let mut semantic = Map::new();
    semantic.insert("item_count".to_string(), Value::from(items.len() as u64));
    semantic.insert(
        "sample_items".to_string(),
        Value::Array(items.iter().take(12).cloned().map(Value::String).collect()),
    );

    Some(MacosCatalogRecord {
        artifact_key: spec.key.clone(),
        source_path: path.display().to_string(),
        timestamp_unix: infer_timestamp_from_value(root_json),
        primary: format!("finder.sidebar.items={}", items.len()),
        secondary: items.first().cloned(),
        detail: Some("plist_semantic_finder_sidebar".to_string()),
        fields_json: serde_json::to_string(&semantic).ok(),
    })
}

fn build_recent_items_semantic_record(
    spec: &MacosCatalogSpec,
    path: &Path,
    root_json: &Value,
) -> Option<MacosCatalogRecord> {
    let items = collect_leaf_strings_by_key_tokens(
        root_json,
        &["recent", "last", "path", "url", "name", "item"],
        48,
    );
    if items.is_empty() {
        return None;
    }

    let mut semantic = Map::new();
    semantic.insert("item_count".to_string(), Value::from(items.len() as u64));
    semantic.insert(
        "sample_items".to_string(),
        Value::Array(items.iter().take(15).cloned().map(Value::String).collect()),
    );

    Some(MacosCatalogRecord {
        artifact_key: spec.key.clone(),
        source_path: path.display().to_string(),
        timestamp_unix: infer_timestamp_from_value(root_json),
        primary: format!("recent_items.count={}", items.len()),
        secondary: items.first().cloned(),
        detail: Some("plist_semantic_recent_items".to_string()),
        fields_json: serde_json::to_string(&semantic).ok(),
    })
}

fn build_launchservices_semantic_record(
    spec: &MacosCatalogSpec,
    path: &Path,
    root_json: &Value,
) -> Option<MacosCatalogRecord> {
    let handlers = collect_leaf_strings_by_key_tokens(
        root_json,
        &[
            "lshandlerroleall",
            "lshandlerroleviewer",
            "lshandlerroleeditor",
            "bundleidentifier",
            "bundle_id",
        ],
        24,
    );
    let schemes = collect_leaf_strings_by_key_tokens(
        root_json,
        &["lshandlerurlscheme", "urlscheme", "scheme"],
        24,
    );
    let content_types = collect_leaf_strings_by_key_tokens(
        root_json,
        &["lshandlercontenttype", "contenttype", "uti"],
        24,
    );

    if handlers.is_empty() && schemes.is_empty() && content_types.is_empty() {
        return None;
    }

    let mut semantic = Map::new();
    semantic.insert(
        "handler_count".to_string(),
        Value::from(handlers.len() as u64),
    );
    semantic.insert(
        "scheme_count".to_string(),
        Value::from(schemes.len() as u64),
    );
    semantic.insert(
        "content_type_count".to_string(),
        Value::from(content_types.len() as u64),
    );
    if !handlers.is_empty() {
        semantic.insert(
            "sample_handlers".to_string(),
            Value::Array(
                handlers
                    .iter()
                    .take(10)
                    .cloned()
                    .map(Value::String)
                    .collect(),
            ),
        );
    }
    if !schemes.is_empty() {
        semantic.insert(
            "sample_schemes".to_string(),
            Value::Array(
                schemes
                    .iter()
                    .take(10)
                    .cloned()
                    .map(Value::String)
                    .collect(),
            ),
        );
    }
    if !content_types.is_empty() {
        semantic.insert(
            "sample_content_types".to_string(),
            Value::Array(
                content_types
                    .iter()
                    .take(10)
                    .cloned()
                    .map(Value::String)
                    .collect(),
            ),
        );
    }

    Some(MacosCatalogRecord {
        artifact_key: spec.key.clone(),
        source_path: path.display().to_string(),
        timestamp_unix: infer_timestamp_from_value(root_json),
        primary: format!("launchservices.handlers={}", handlers.len()),
        secondary: handlers
            .first()
            .cloned()
            .or_else(|| schemes.first().cloned())
            .or_else(|| content_types.first().cloned()),
        detail: Some("plist_semantic_launchservices".to_string()),
        fields_json: serde_json::to_string(&semantic).ok(),
    })
}

fn build_dock_semantic_record(
    spec: &MacosCatalogSpec,
    path: &Path,
    root_json: &Value,
) -> Option<MacosCatalogRecord> {
    build_token_semantic_record(
        spec,
        path,
        root_json,
        "dock.items",
        "plist_semantic_dock",
        &[
            "persistent-apps",
            "recent-apps",
            "_cfurlstring",
            "bundleidentifier",
            "path",
            "name",
        ],
        40,
    )
}

fn build_preview_recents_semantic_record(
    spec: &MacosCatalogSpec,
    path: &Path,
    root_json: &Value,
) -> Option<MacosCatalogRecord> {
    build_token_semantic_record(
        spec,
        path,
        root_json,
        "preview.recents",
        "plist_semantic_preview_recents",
        &["recent", "path", "url", "name", "document"],
        40,
    )
}

fn build_office_mru_semantic_record(
    spec: &MacosCatalogSpec,
    path: &Path,
    root_json: &Value,
) -> Option<MacosCatalogRecord> {
    build_token_semantic_record(
        spec,
        path,
        root_json,
        "office.mru.items",
        "plist_semantic_office_mru",
        &["mru", "path", "url", "file", "name", "link"],
        40,
    )
}

fn build_mail_rules_semantic_record(
    spec: &MacosCatalogSpec,
    path: &Path,
    root_json: &Value,
) -> Option<MacosCatalogRecord> {
    build_token_semantic_record(
        spec,
        path,
        root_json,
        "mail.rules",
        "plist_semantic_mail_rules",
        &[
            "rule",
            "criteria",
            "condition",
            "action",
            "mailbox",
            "account",
            "name",
        ],
        48,
    )
}

fn build_mail_accounts_semantic_record(
    spec: &MacosCatalogSpec,
    path: &Path,
    root_json: &Value,
) -> Option<MacosCatalogRecord> {
    build_token_semantic_record(
        spec,
        path,
        root_json,
        "mail.accounts",
        "plist_semantic_mail_accounts",
        &[
            "account",
            "email",
            "hostname",
            "imap",
            "smtp",
            "username",
            "displayname",
            "server",
        ],
        48,
    )
}

fn build_loginwindow_semantic_record(
    spec: &MacosCatalogSpec,
    path: &Path,
    root_json: &Value,
) -> Option<MacosCatalogRecord> {
    build_token_semantic_record(
        spec,
        path,
        root_json,
        "loginwindow.items",
        "plist_semantic_loginwindow",
        &[
            "lastuser",
            "autologin",
            "showfullnam",
            "showinputmen",
            "guest",
            "name",
            "user",
            "loginwindow",
        ],
        40,
    )
}

fn build_network_preferences_semantic_record(
    spec: &MacosCatalogSpec,
    path: &Path,
    root_json: &Value,
) -> Option<MacosCatalogRecord> {
    build_token_semantic_record(
        spec,
        path,
        root_json,
        "network.preferences",
        "plist_semantic_network_preferences",
        &[
            "proxy",
            "http",
            "https",
            "socks",
            "vpn",
            "service",
            "dns",
            "server",
            "interface",
            "scnetwork",
        ],
        60,
    )
}

fn build_system_version_semantic_record(
    spec: &MacosCatalogSpec,
    path: &Path,
    fields: &Map<String, Value>,
    root_json: &Value,
) -> Option<MacosCatalogRecord> {
    let product_name = get_field_string_ci(fields, "ProductName");
    let product_version = get_field_string_ci(fields, "ProductVersion");
    let build_version = get_field_string_ci(fields, "ProductBuildVersion")
        .or_else(|| get_field_string_ci(fields, "BuildVersion"));

    if product_name.is_none() && product_version.is_none() && build_version.is_none() {
        return None;
    }

    let primary = match (product_name.clone(), product_version.clone()) {
        (Some(name), Some(version)) => format!("system.version={} {}", name, version),
        (Some(name), None) => format!("system.version={}", name),
        (None, Some(version)) => format!("system.version={}", version),
        _ => format!("system.version.source={}", path.display()),
    };
    let secondary = build_version
        .clone()
        .map(|v| format!("build={}", v))
        .filter(|v| !primary.contains(v));

    let mut semantic = Map::new();
    if let Some(v) = product_name {
        semantic.insert("product_name".to_string(), Value::String(v));
    }
    if let Some(v) = product_version {
        semantic.insert("product_version".to_string(), Value::String(v));
    }
    if let Some(v) = build_version {
        semantic.insert("build_version".to_string(), Value::String(v));
    }

    Some(MacosCatalogRecord {
        artifact_key: spec.key.clone(),
        source_path: path.display().to_string(),
        timestamp_unix: infer_timestamp_from_value(root_json),
        primary,
        secondary,
        detail: Some("plist_semantic_system_version".to_string()),
        fields_json: serde_json::to_string(&semantic).ok(),
    })
}

fn build_time_machine_semantic_record(
    spec: &MacosCatalogSpec,
    path: &Path,
    root_json: &Value,
) -> Option<MacosCatalogRecord> {
    build_token_semantic_record(
        spec,
        path,
        root_json,
        "time_machine.items",
        "plist_semantic_time_machine",
        &[
            "destination",
            "backup",
            "lastbackup",
            "snapshot",
            "volume",
            "machinename",
            "start",
            "date",
        ],
        60,
    )
}

fn build_network_interfaces_semantic_record(
    spec: &MacosCatalogSpec,
    path: &Path,
    root_json: &Value,
) -> Option<MacosCatalogRecord> {
    build_token_semantic_record(
        spec,
        path,
        root_json,
        "network.interfaces",
        "plist_semantic_network_interfaces",
        &[
            "interface",
            "bsdname",
            "device",
            "hardware",
            "macaddress",
            "scnetworkinterface",
            "type",
            "name",
        ],
        60,
    )
}

fn build_wifi_known_networks_semantic_record(
    spec: &MacosCatalogSpec,
    path: &Path,
    root_json: &Value,
) -> Option<MacosCatalogRecord> {
    build_token_semantic_record(
        spec,
        path,
        root_json,
        "wifi.known_networks",
        "plist_semantic_wifi_known_networks",
        &[
            "ssid",
            "knownnetwork",
            "security",
            "lastconnected",
            "channel",
            "network",
            "airport",
            "bssid",
        ],
        80,
    )
}

fn build_installhistory_semantic_record(
    spec: &MacosCatalogSpec,
    path: &Path,
    root_json: &Value,
) -> Option<MacosCatalogRecord> {
    build_token_semantic_record(
        spec,
        path,
        root_json,
        "installhistory.items",
        "plist_semantic_installhistory",
        &[
            "displayname",
            "display version",
            "displayversion",
            "processname",
            "packag",
            "version",
            "install date",
            "installdate",
        ],
        80,
    )
}

fn build_bluetooth_paired_semantic_record(
    spec: &MacosCatalogSpec,
    path: &Path,
    root_json: &Value,
) -> Option<MacosCatalogRecord> {
    build_token_semantic_record(
        spec,
        path,
        root_json,
        "bluetooth.paired_devices",
        "plist_semantic_bluetooth_paired",
        &[
            "device",
            "name",
            "address",
            "mac",
            "paired",
            "lastseen",
            "lastconnected",
            "vendor",
            "product",
        ],
        80,
    )
}

fn build_airdrop_semantic_record(
    spec: &MacosCatalogSpec,
    path: &Path,
    root_json: &Value,
) -> Option<MacosCatalogRecord> {
    build_token_semantic_record(
        spec,
        path,
        root_json,
        "network.airdrop.items",
        "plist_semantic_airdrop",
        &[
            "airdrop", "discover", "peer", "receiver", "sender", "device", "last", "transfer",
        ],
        80,
    )
}

fn build_airplay_semantic_record(
    spec: &MacosCatalogSpec,
    path: &Path,
    root_json: &Value,
) -> Option<MacosCatalogRecord> {
    build_token_semantic_record(
        spec,
        path,
        root_json,
        "network.airplay.items",
        "plist_semantic_airplay",
        &[
            "airplay", "route", "device", "receiver", "target", "name", "bonjour", "last",
        ],
        80,
    )
}

fn build_hotspot_semantic_record(
    spec: &MacosCatalogSpec,
    path: &Path,
    root_json: &Value,
) -> Option<MacosCatalogRecord> {
    build_token_semantic_record(
        spec,
        path,
        root_json,
        "network.hotspot.items",
        "plist_semantic_hotspot",
        &[
            "hotspot",
            "personal",
            "tether",
            "ssid",
            "password",
            "last",
            "device",
            "interface",
        ],
        80,
    )
}

fn build_private_relay_semantic_record(
    spec: &MacosCatalogSpec,
    path: &Path,
    root_json: &Value,
) -> Option<MacosCatalogRecord> {
    build_token_semantic_record(
        spec,
        path,
        root_json,
        "network.icloud_private_relay.items",
        "plist_semantic_private_relay",
        &[
            "private", "relay", "icloud", "enabled", "country", "region", "last", "status",
        ],
        80,
    )
}

fn build_location_services_semantic_record(
    spec: &MacosCatalogSpec,
    path: &Path,
    root_json: &Value,
) -> Option<MacosCatalogRecord> {
    build_token_semantic_record(
        spec,
        path,
        root_json,
        "network.location_services.items",
        "plist_semantic_location_services",
        &[
            "location",
            "service",
            "authorized",
            "enabled",
            "bundle",
            "identifier",
            "last",
            "timestamp",
        ],
        80,
    )
}

fn build_print_recent_jobs_semantic_record(
    spec: &MacosCatalogSpec,
    path: &Path,
    root_json: &Value,
) -> Option<MacosCatalogRecord> {
    build_token_semantic_record(
        spec,
        path,
        root_json,
        "print.recent_jobs.items",
        "plist_semantic_print_recent_jobs",
        &[
            "print", "printer", "job", "document", "queue", "last", "name", "host",
        ],
        80,
    )
}

fn build_finder_tags_semantic_record(
    spec: &MacosCatalogSpec,
    path: &Path,
    root_json: &Value,
) -> Option<MacosCatalogRecord> {
    build_token_semantic_record(
        spec,
        path,
        root_json,
        "finder.tags.items",
        "plist_semantic_finder_tags",
        &["tag", "finder", "label", "color", "name", "recent", "item"],
        80,
    )
}

fn build_saved_state_windows_semantic_record(
    spec: &MacosCatalogSpec,
    path: &Path,
    root_json: &Value,
) -> Option<MacosCatalogRecord> {
    build_token_semantic_record(
        spec,
        path,
        root_json,
        "saved_state.windows.items",
        "plist_semantic_saved_state_windows",
        &[
            "window",
            "frame",
            "position",
            "workspace",
            "session",
            "state",
            "title",
            "recent",
        ],
        80,
    )
}

fn build_token_semantic_record(
    spec: &MacosCatalogSpec,
    path: &Path,
    root_json: &Value,
    primary_prefix: &str,
    detail: &str,
    key_tokens: &[&str],
    max_items: usize,
) -> Option<MacosCatalogRecord> {
    let items = collect_leaf_strings_by_key_tokens(root_json, key_tokens, max_items);
    if items.is_empty() {
        return None;
    }

    let mut semantic = Map::new();
    semantic.insert("item_count".to_string(), Value::from(items.len() as u64));
    semantic.insert(
        "sample_items".to_string(),
        Value::Array(items.iter().take(12).cloned().map(Value::String).collect()),
    );

    Some(MacosCatalogRecord {
        artifact_key: spec.key.clone(),
        source_path: path.display().to_string(),
        timestamp_unix: infer_timestamp_from_value(root_json),
        primary: format!("{}={}", primary_prefix, items.len()),
        secondary: items.first().cloned(),
        detail: Some(detail.to_string()),
        fields_json: serde_json::to_string(&semantic).ok(),
    })
}

fn get_field_case_insensitive<'a>(fields: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    fields
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v)
}

fn get_field_string_ci(fields: &Map<String, Value>, key: &str) -> Option<String> {
    get_field_case_insensitive(fields, key)
        .map(value_to_short_string)
        .filter(|v| !v.is_empty())
}

fn get_field_bool_ci(fields: &Map<String, Value>, key: &str) -> Option<bool> {
    get_field_case_insensitive(fields, key).and_then(|v| match v {
        Value::Bool(b) => Some(*b),
        Value::String(s) => match s.trim().to_ascii_lowercase().as_str() {
            "true" | "yes" | "1" => Some(true),
            "false" | "no" | "0" => Some(false),
            _ => None,
        },
        _ => None,
    })
}

fn get_program_arguments(fields: &Map<String, Value>) -> Option<String> {
    let value = get_field_case_insensitive(fields, "programarguments")?;
    let arr = value.as_array()?;
    let args: Vec<String> = arr
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.trim().to_string()))
        .filter(|s| !s.is_empty())
        .collect();
    if args.is_empty() {
        None
    } else {
        Some(args.join(" "))
    }
}

fn collect_leaf_strings_by_key_tokens(
    root_json: &Value,
    key_tokens: &[&str],
    max_items: usize,
) -> Vec<String> {
    if key_tokens.is_empty() || max_items == 0 {
        return Vec::new();
    }
    let mut leaves = Vec::new();
    flatten_json_leaves_limited("", root_json, &mut leaves, 0, max_items.saturating_mul(16));

    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for (key_path, value) in leaves {
        let key_lc = key_path.to_ascii_lowercase();
        if !key_tokens.iter().any(|token| key_lc.contains(token)) {
            continue;
        }
        let rendered = value_to_short_string(&value);
        if rendered.is_empty() {
            continue;
        }
        if seen.insert(rendered.clone()) {
            out.push(rendered);
            if out.len() >= max_items {
                break;
            }
        }
    }
    out
}

fn flatten_json_leaves_limited(
    prefix: &str,
    value: &Value,
    out: &mut Vec<(String, Value)>,
    depth: usize,
    limit: usize,
) {
    if depth > 12 || out.len() >= limit {
        return;
    }
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                if out.len() >= limit {
                    break;
                }
                let next = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{}.{}", prefix, k)
                };
                flatten_json_leaves_limited(&next, v, out, depth + 1, limit);
            }
        }
        Value::Array(items) => {
            for (idx, item) in items.iter().enumerate() {
                if out.len() >= limit {
                    break;
                }
                let next = if prefix.is_empty() {
                    format!("[{}]", idx)
                } else {
                    format!("{}[{}]", prefix, idx)
                };
                flatten_json_leaves_limited(&next, item, out, depth + 1, limit);
            }
        }
        _ => {
            if !prefix.is_empty() {
                out.push((prefix.to_string(), value.clone()));
            }
        }
    }
}

fn flatten_plist_leaves(
    prefix: &str,
    value: &PlistValue,
    out: &mut Vec<(String, Value)>,
    depth: usize,
    limit: usize,
) {
    if depth > 12 || out.len() >= limit {
        return;
    }
    match value {
        PlistValue::Dictionary(map) => {
            for (k, v) in map {
                if out.len() >= limit {
                    break;
                }
                let next = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{}.{}", prefix, k)
                };
                flatten_plist_leaves(&next, v, out, depth + 1, limit);
            }
        }
        PlistValue::Array(items) => {
            for (idx, item) in items.iter().enumerate() {
                if out.len() >= limit {
                    break;
                }
                let next = if prefix.is_empty() {
                    format!("[{}]", idx)
                } else {
                    format!("{}[{}]", prefix, idx)
                };
                flatten_plist_leaves(&next, item, out, depth + 1, limit);
            }
        }
        _ => {
            if prefix.is_empty() {
                return;
            }
            let leaf = plist_leaf_to_json(value);
            out.push((prefix.to_string(), leaf));
        }
    }
}

fn plist_leaf_to_json(value: &PlistValue) -> Value {
    if let Ok(json) = serde_json::to_value(value) {
        return match &json {
            // For binary plist blobs, avoid returning huge integer arrays as "primary".
            Value::Array(items) if items.len() > 32 => {
                Value::String(format!("[binary_data:{} bytes]", items.len()))
            }
            _ => json,
        };
    }
    Value::String(format!("{:?}", value))
}

fn value_to_short_string(value: &Value) -> String {
    let raw = match value {
        Value::Null => String::new(),
        Value::Bool(v) => v.to_string(),
        Value::Number(v) => v.to_string(),
        Value::String(v) => v.trim().to_string(),
        _ => value.to_string(),
    };
    if raw.len() > 180 {
        format!("{}...", &raw[..180])
    } else {
        raw
    }
}

fn infer_timestamp_from_value(value: &Value) -> Option<u64> {
    match value {
        Value::Object(map) => infer_timestamp_from_fields(map),
        Value::Array(items) => items.iter().find_map(infer_timestamp_from_value),
        _ => parse_timestamp_value(value),
    }
}

fn resolve_candidate_paths(spec: &MacosCatalogSpec) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if !spec.env_key.trim().is_empty() {
        out.extend(paths_from_env(&spec.env_key));
    }
    for raw in &spec.candidates {
        if let Some(path) = resolve_template_path(raw) {
            out.push(path);
        }
    }
    dedup_paths(out)
}

fn paths_from_env(key: &str) -> Vec<PathBuf> {
    let Ok(raw) = env::var(key) else {
        return Vec::new();
    };
    raw.split(';')
        .flat_map(|s| s.split(','))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(resolve_template_path)
        .collect()
}

fn resolve_template_path(raw: &str) -> Option<PathBuf> {
    let mut candidate = raw.trim().to_string();
    if candidate.is_empty() {
        return None;
    }
    if candidate.contains("{HOME}") {
        let home = env::var("HOME").or_else(|_| env::var("USERPROFILE")).ok()?;
        candidate = candidate.replace("{HOME}", &home);
    }
    Some(PathBuf::from(candidate))
}

fn dedup_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for path in paths {
        let key = path.to_string_lossy().to_string();
        if seen.insert(key) {
            out.push(path);
        }
    }
    out
}

fn parse_line_timestamp(line: &str) -> Option<u64> {
    if let Some(rest) = line.strip_prefix(": ") {
        let mut parts = rest.splitn(2, ';');
        let meta = parts.next().unwrap_or_default();
        return meta
            .split(':')
            .next()
            .and_then(|x| x.trim().parse::<u64>().ok());
    }
    if let Some(rest) = line.strip_prefix('#') {
        if rest.chars().all(|c| c.is_ascii_digit()) {
            return rest.parse::<u64>().ok();
        }
    }
    None
}

fn clean_shell_line(line: &str) -> String {
    if let Some(rest) = line.strip_prefix(": ") {
        let mut parts = rest.splitn(2, ';');
        let _ = parts.next();
        return parts.next().unwrap_or_default().trim().to_string();
    }
    line.to_string()
}

fn value_ref_to_json(value: ValueRef<'_>) -> Value {
    match value {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(v) => Value::from(v),
        ValueRef::Real(v) => Value::from(v),
        ValueRef::Text(v) => Value::from(String::from_utf8_lossy(v).to_string()),
        ValueRef::Blob(v) => {
            if let Some(plist_json) = parse_plist_from_blob(v) {
                return plist_json;
            }
            let mut hex = String::with_capacity(v.len() * 2);
            for b in v.iter().take(64) {
                use std::fmt::Write as _;
                let _ = write!(&mut hex, "{:02x}", b);
            }
            Value::from(format!(
                "hex:{}{}",
                hex,
                if v.len() > 64 { "..." } else { "" }
            ))
        }
    }
}

fn parse_plist_from_blob(blob: &[u8]) -> Option<Value> {
    if !looks_like_plist_bytes(blob) {
        return None;
    }
    let root = PlistValue::from_reader(Cursor::new(blob)).ok()?;
    let json = serde_json::to_value(root).ok()?;
    Some(compact_json_value(json))
}

fn compact_json_value(value: Value) -> Value {
    match value {
        Value::Array(items) if items.len() > 64 => {
            Value::String(format!("[array:{} items]", items.len()))
        }
        Value::String(s) if s.len() > 256 => Value::String(format!("{}...", &s[..256])),
        other => other,
    }
}

fn infer_timestamp_from_fields(fields: &Map<String, Value>) -> Option<u64> {
    let preferred = [
        "timestamp",
        "time",
        "date",
        "created",
        "modified",
        "last_used",
        "last_visit_time",
        "visit_time",
        "start_time",
        "end_time",
        "last_modified",
        "zdate",
        "zstartdate",
    ];

    for key in preferred {
        if let Some(value) = find_field_case_insensitive(fields, key) {
            if let Some(ts) = parse_timestamp_value(value) {
                return Some(ts);
            }
        }
    }

    for (key, value) in fields {
        let lower = key.to_ascii_lowercase();
        if (lower.contains("time")
            || lower.contains("date")
            || lower.contains("created")
            || lower.contains("modified")
            || lower.contains("visit"))
            && parse_timestamp_value(value).is_some()
        {
            return parse_timestamp_value(value);
        }
    }

    None
}

fn parse_timestamp_value(value: &Value) -> Option<u64> {
    match value {
        Value::Number(n) => n.as_f64().and_then(normalize_possible_apple_time),
        Value::String(s) => {
            if let Ok(n) = s.trim().parse::<f64>() {
                return normalize_possible_apple_time(n);
            }
            if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s.trim()) {
                return Some(dt.timestamp().max(0) as u64);
            }
            None
        }
        Value::Object(map) => infer_timestamp_from_fields(map),
        Value::Array(items) => items.iter().find_map(parse_timestamp_value),
        _ => None,
    }
}

fn normalize_possible_apple_time(raw: f64) -> Option<u64> {
    if !raw.is_finite() || raw <= 0.0 {
        return None;
    }
    if raw > 9_999_999_999.0 {
        return Some((raw / 1_000_000.0) as u64);
    }
    if raw >= 1_000_000_000.0 {
        return Some(raw as u64);
    }
    let unix = (raw as i64).saturating_add(APPLE_UNIX_EPOCH_OFFSET_SECS);
    if unix > 0 {
        Some(unix as u64)
    } else {
        None
    }
}

fn infer_primary(fields: &Map<String, Value>) -> String {
    let preferred = [
        "url",
        "path",
        "command",
        "name",
        "title",
        "identifier",
        "bundle_id",
        "message",
        "query",
        "host",
        "domain",
        "origin",
        "value",
    ];
    for key in preferred {
        if let Some(value) = find_field_case_insensitive(fields, key) {
            if let Some(s) = value.as_str() {
                let trimmed = s.trim();
                if !trimmed.is_empty() {
                    return trimmed.to_string();
                }
            }
        }
    }

    for value in fields.values() {
        if let Some(s) = value.as_str() {
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }

    for value in fields.values() {
        let rendered = value_to_short_string(value);
        if !rendered.is_empty() {
            return rendered;
        }
    }

    String::new()
}

fn infer_secondary(fields: &Map<String, Value>, primary: &str) -> Option<String> {
    let preferred = [
        "title",
        "origin_url",
        "data_url",
        "username",
        "agent_name",
        "bundle_identifier",
        "email",
        "account",
        "sender",
    ];
    for key in preferred {
        if let Some(value) = find_field_case_insensitive(fields, key) {
            if let Some(s) = value.as_str() {
                let trimmed = s.trim();
                if !trimmed.is_empty() && trimmed != primary {
                    return Some(trimmed.to_string());
                }
            }
        }
    }
    None
}

fn summarize_fields(fields: &Map<String, Value>) -> String {
    let mut segments = Vec::new();
    for (k, v) in fields.iter().take(6) {
        let value = match v {
            Value::Null => "null".to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Number(n) => n.to_string(),
            Value::String(s) => {
                let clipped = if s.len() > 96 {
                    format!("{}...", &s[..96])
                } else {
                    s.clone()
                };
                clipped.replace('\n', " ")
            }
            _ => v.to_string(),
        };
        segments.push(format!("{}={}", k, value));
    }
    segments.join(", ")
}

fn find_field_case_insensitive<'a>(fields: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    let key_lower = key.to_ascii_lowercase();
    fields
        .iter()
        .find(|(k, _)| k.to_ascii_lowercase() == key_lower)
        .map(|(_, v)| v)
}

fn ensure_limit(query: &str, default_limit: usize) -> String {
    let q = query.trim();
    if q.to_ascii_lowercase().contains(" limit ") {
        q.to_string()
    } else {
        format!("{} LIMIT {}", q, default_limit)
    }
}

fn looks_like_plist_file(path: &Path) -> bool {
    let Ok(mut file) = strata_fs::File::open(path) else {
        return false;
    };
    let mut buf = [0u8; MAX_PLIST_SNIFF_BYTES];
    let Ok(read) = file.read(&mut buf) else {
        return false;
    };
    looks_like_plist_bytes(&buf[..read])
}

fn looks_like_plist_bytes(bytes: &[u8]) -> bool {
    if bytes.starts_with(b"bplist00") {
        return true;
    }
    let trimmed = String::from_utf8_lossy(bytes);
    let lower = trimmed.to_ascii_lowercase();
    lower.contains("<plist") || lower.contains("<?xml")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn has_at_least_260_macos_catalog_specs() {
        let count = macos_catalog_specs().len();
        assert!(count >= 260, "expected >=260 specs, got {}", count);
    }

    #[test]
    fn catalog_keys_are_unique() {
        let specs = macos_catalog_specs();
        let mut set = std::collections::HashSet::new();
        for spec in specs {
            assert!(set.insert(spec.key), "duplicate macOS catalog key found");
        }
    }

    #[test]
    fn parses_text_artifact_lines() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(".zsh_history");
        std::fs::write(&path, ": 1700000000:0;ls -la\npwd\n").unwrap();

        let spec = text_spec(
            "macos.shell.zsh_history",
            "zsh history",
            "FORENSIC_TMP_ZSH",
            vec![path.display().to_string()],
        );
        let rows = parse_spec(&spec);
        assert!(!rows.is_empty());
        assert_eq!(rows[0].artifact_key, "macos.shell.zsh_history");
    }

    #[test]
    fn parses_sqlite_artifact_rows() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("sample.db");
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE items (url TEXT, title TEXT, last_visit_time REAL);
             INSERT INTO items (url, title, last_visit_time) VALUES ('https://example.com', 'Example', 1000.0);",
        )
        .unwrap();
        drop(conn);

        let spec = sqlite_spec(
            "macos.test.sqlite",
            "test sqlite parser",
            "",
            vec![db_path.display().to_string()],
            "SELECT url, title, last_visit_time FROM items",
        );
        let rows = parse_spec(&spec);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].primary, "https://example.com");
        assert!(rows[0].timestamp_unix.is_some());
    }

    #[test]
    fn parses_sqlite_plist_blob_rows() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("blob_sample.db");
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch("CREATE TABLE items (meta BLOB);")
            .unwrap();
        let plist_blob = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>label</key><string>com.example.blob</string>
  <key>last_seen</key><date>2026-03-08T05:00:00Z</date>
</dict>
</plist>"#;
        conn.execute("INSERT INTO items (meta) VALUES (?1)", [&plist_blob[..]])
            .unwrap();
        drop(conn);

        let spec = sqlite_spec(
            "macos.test.sqlite_blob",
            "test sqlite plist blob parser",
            "",
            vec![db_path.display().to_string()],
            "SELECT meta FROM items",
        );
        let rows = parse_spec(&spec);
        assert_eq!(rows.len(), 1);
        assert!(
            rows[0].primary.contains("com.example.blob"),
            "expected plist blob value surfaced in primary"
        );
    }

    #[test]
    fn parses_xml_plist_artifact_rows() {
        let dir = tempdir().unwrap();
        let plist_path = dir.path().join("com.example.test.plist");
        let plist_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.example.agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/bin/python3</string>
    <string>/tmp/run.py</string>
  </array>
  <key>LastSeen</key>
  <date>2026-03-08T04:00:00Z</date>
</dict>
</plist>
"#;
        std::fs::write(&plist_path, plist_xml).unwrap();

        let spec = text_spec(
            "macos.launchagents.user",
            "User LaunchAgents plist files",
            "",
            vec![plist_path.display().to_string()],
        );
        let rows = parse_spec(&spec);
        assert!(
            rows.iter()
                .any(|r| r.detail.as_deref() == Some("plist_semantic_launchd")),
            "expected semantic launchd summary record"
        );
        assert!(
            rows.iter()
                .any(|r| r.primary.contains("Label=com.example.agent")),
            "expected Label leaf in plist output"
        );
        assert!(
            rows.iter().any(|r| r.timestamp_unix.is_some()),
            "expected at least one timestamp field from plist"
        );
    }

    #[test]
    fn parses_plist_focused_directory_artifact_rows() {
        let dir = tempdir().unwrap();
        let launchagents = dir.path().join("LaunchAgents");
        std::fs::create_dir_all(&launchagents).unwrap();

        let plist_path = launchagents.join("com.example.agent.plist");
        let plist_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.example.agent</string>
</dict>
</plist>
"#;
        std::fs::write(&plist_path, plist_xml).unwrap();
        std::fs::write(launchagents.join("README.txt"), "not plist").unwrap();

        let spec = text_spec(
            "macos.launchagents.system",
            "System LaunchAgents plist files",
            "",
            vec![launchagents.display().to_string()],
        );
        let rows = parse_spec(&spec);
        assert!(!rows.is_empty(), "expected plist rows from directory scan");
        assert!(
            rows.iter().all(|r| r.source_path.ends_with(".plist")),
            "expected plist-backed records for plist-focused directory parser"
        );
    }

    #[test]
    fn parses_plist_without_extension_from_directory_scan() {
        let dir = tempdir().unwrap();
        let prefs = dir.path().join("Preferences");
        std::fs::create_dir_all(&prefs).unwrap();
        let plist_no_ext = prefs.join("com.example.agent");
        let plist_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.example.noext</string>
</dict>
</plist>"#;
        std::fs::write(&plist_no_ext, plist_xml).unwrap();

        let spec = text_spec(
            "macos.preferences.global",
            "Global preferences plist",
            "",
            vec![prefs.display().to_string()],
        );
        let rows = parse_spec(&spec);
        assert!(
            !rows.is_empty(),
            "expected plist rows from no-extension plist"
        );
        assert!(
            rows.iter().any(|r| r.primary.contains("com.example.noext")),
            "expected no-extension plist content to be parsed"
        );
    }

    #[test]
    fn adds_preferences_semantic_record() {
        let dir = tempdir().unwrap();
        let plist_path = dir.path().join(".GlobalPreferences.plist");
        let plist_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>AppleLocale</key>
  <string>en_US</string>
  <key>AppleLanguages</key>
  <array>
    <string>en-US</string>
    <string>fr-US</string>
  </array>
</dict>
</plist>"#;
        std::fs::write(&plist_path, plist_xml).unwrap();

        let spec = text_spec(
            "macos.preferences.global",
            "Global preferences plist",
            "",
            vec![plist_path.display().to_string()],
        );
        let rows = parse_spec(&spec);
        assert!(
            rows.iter()
                .any(|r| r.detail.as_deref() == Some("plist_semantic_preferences")),
            "expected semantic preferences summary record"
        );
        assert!(
            rows.iter()
                .any(|r| r.primary.contains("preferences.domain=")),
            "expected preferences semantic primary"
        );
    }

    #[test]
    fn adds_loginitems_semantic_record() {
        let dir = tempdir().unwrap();
        let plist_path = dir.path().join("com.apple.loginitems.plist");
        let plist_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>SessionItems</key>
  <dict>
    <key>CustomListItems</key>
    <array>
      <dict>
        <key>Name</key><string>Slack</string>
        <key>Path</key><string>/Applications/Slack.app</string>
        <key>BundleIdentifier</key><string>com.tinyspeck.slackmacgap</string>
      </dict>
    </array>
  </dict>
</dict>
</plist>"#;
        std::fs::write(&plist_path, plist_xml).unwrap();

        let spec = text_spec(
            "macos.loginitems.shared_file_list",
            "Shared file list login items",
            "",
            vec![plist_path.display().to_string()],
        );
        let rows = parse_spec(&spec);
        assert!(
            rows.iter()
                .any(|r| r.detail.as_deref() == Some("plist_semantic_loginitems")),
            "expected semantic loginitems summary record"
        );
        assert!(
            rows.iter().any(|r| r.primary.contains("loginitems.")),
            "expected loginitems semantic primary"
        );
    }

    #[test]
    fn adds_finder_sidebar_semantic_record() {
        let dir = tempdir().unwrap();
        let plist_path = dir.path().join("com.apple.sidebarlists.plist");
        let plist_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>favorites</key>
  <array>
    <dict>
      <key>Name</key><string>Desktop</string>
      <key>Path</key><string>/Users/test/Desktop</string>
    </dict>
    <dict>
      <key>Name</key><string>Documents</string>
      <key>Path</key><string>/Users/test/Documents</string>
    </dict>
  </array>
</dict>
</plist>"#;
        std::fs::write(&plist_path, plist_xml).unwrap();

        let spec = text_spec(
            "macos.finder.sidebarlists",
            "Finder sidebarlists plist",
            "",
            vec![plist_path.display().to_string()],
        );
        let rows = parse_spec(&spec);
        assert!(
            rows.iter()
                .any(|r| r.detail.as_deref() == Some("plist_semantic_finder_sidebar")),
            "expected semantic finder sidebar summary record"
        );
        assert!(
            rows.iter()
                .any(|r| r.primary.contains("finder.sidebar.items=")),
            "expected finder sidebar semantic primary"
        );
    }

    #[test]
    fn adds_recent_items_semantic_record() {
        let dir = tempdir().unwrap();
        let plist_path = dir.path().join("com.apple.recentitems.plist");
        let plist_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>RecentItems</key>
  <array>
    <dict>
      <key>Name</key><string>report.docx</string>
      <key>Path</key><string>/Users/test/Documents/report.docx</string>
    </dict>
    <dict>
      <key>Name</key><string>notes.txt</string>
      <key>Path</key><string>/Users/test/Documents/notes.txt</string>
    </dict>
  </array>
  <key>LastUsedDate</key><date>2026-03-08T06:00:00Z</date>
</dict>
</plist>"#;
        std::fs::write(&plist_path, plist_xml).unwrap();

        let spec = text_spec(
            "macos.recent_items",
            "Recent Items plist traces",
            "",
            vec![plist_path.display().to_string()],
        );
        let rows = parse_spec(&spec);
        assert!(
            rows.iter()
                .any(|r| r.detail.as_deref() == Some("plist_semantic_recent_items")),
            "expected semantic recent items summary record"
        );
        assert!(
            rows.iter()
                .any(|r| r.primary.contains("recent_items.count=")),
            "expected recent items semantic primary"
        );
    }

    #[test]
    fn adds_launchservices_semantic_record() {
        let dir = tempdir().unwrap();
        let plist_path = dir.path().join("com.apple.launchservices.secure.plist");
        let plist_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>LSHandlers</key>
  <array>
    <dict>
      <key>LSHandlerURLScheme</key><string>http</string>
      <key>LSHandlerRoleAll</key><string>com.apple.Safari</string>
    </dict>
    <dict>
      <key>LSHandlerContentType</key><string>public.html</string>
      <key>LSHandlerRoleAll</key><string>com.apple.Safari</string>
    </dict>
  </array>
</dict>
</plist>"#;
        std::fs::write(&plist_path, plist_xml).unwrap();

        let spec = text_spec(
            "macos.launchservices.secure",
            "LaunchServices secure plist records",
            "",
            vec![plist_path.display().to_string()],
        );
        let rows = parse_spec(&spec);
        assert!(
            rows.iter()
                .any(|r| r.detail.as_deref() == Some("plist_semantic_launchservices")),
            "expected semantic launchservices summary record"
        );
        assert!(
            rows.iter()
                .any(|r| r.primary.contains("launchservices.handlers=")),
            "expected launchservices semantic primary"
        );
    }

    #[test]
    fn adds_dock_semantic_record() {
        let dir = tempdir().unwrap();
        let plist_path = dir.path().join("com.apple.dock.plist");
        let plist_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>persistent-apps</key>
  <array>
    <dict>
      <key>tile-data</key>
      <dict>
        <key>file-data</key>
        <dict>
          <key>_CFURLString</key><string>/Applications/Safari.app</string>
        </dict>
      </dict>
    </dict>
  </array>
</dict>
</plist>"#;
        std::fs::write(&plist_path, plist_xml).unwrap();

        let spec = text_spec(
            "macos.dock.persistent_apps",
            "Dock persistent app list",
            "",
            vec![plist_path.display().to_string()],
        );
        let rows = parse_spec(&spec);
        assert!(
            rows.iter()
                .any(|r| r.detail.as_deref() == Some("plist_semantic_dock")),
            "expected semantic dock summary record"
        );
        assert!(
            rows.iter().any(|r| r.primary.contains("dock.items=")),
            "expected dock semantic primary"
        );
    }

    #[test]
    fn adds_preview_recents_semantic_record() {
        let dir = tempdir().unwrap();
        let plist_path = dir.path().join("com.apple.Preview.recents.plist");
        let plist_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>NSRecentlyUsedDocuments</key>
  <array>
    <string>/Users/test/Documents/invoice.pdf</string>
    <string>/Users/test/Documents/report.pdf</string>
  </array>
</dict>
</plist>"#;
        std::fs::write(&plist_path, plist_xml).unwrap();

        let spec = text_spec(
            "macos.preview.recents",
            "Preview recents plist",
            "",
            vec![plist_path.display().to_string()],
        );
        let rows = parse_spec(&spec);
        assert!(
            rows.iter()
                .any(|r| r.detail.as_deref() == Some("plist_semantic_preview_recents")),
            "expected semantic preview recents summary record"
        );
        assert!(
            rows.iter().any(|r| r.primary.contains("preview.recents=")),
            "expected preview recents semantic primary"
        );
    }

    #[test]
    fn adds_office_mru_semantic_record() {
        let dir = tempdir().unwrap();
        let plist_path = dir.path().join("com.microsoft.office.mru.plist");
        let plist_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>14\File MRU\XCEL</key>
  <array>
    <dict>
      <key>Name</key><string>budget.xlsx</string>
      <key>Path</key><string>/Users/test/Documents/budget.xlsx</string>
    </dict>
  </array>
</dict>
</plist>"#;
        std::fs::write(&plist_path, plist_xml).unwrap();

        let spec = text_spec(
            "macos.office.mru",
            "Microsoft Office MRU plist/cache",
            "",
            vec![plist_path.display().to_string()],
        );
        let rows = parse_spec(&spec);
        assert!(
            rows.iter()
                .any(|r| r.detail.as_deref() == Some("plist_semantic_office_mru")),
            "expected semantic office mru summary record"
        );
        assert!(
            rows.iter().any(|r| r.primary.contains("office.mru.items=")),
            "expected office mru semantic primary"
        );
    }

    #[test]
    fn adds_mail_rules_semantic_record() {
        let dir = tempdir().unwrap();
        let plist_path = dir.path().join("MessageRules.plist");
        let plist_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Rules</key>
  <array>
    <dict>
      <key>RuleName</key><string>Flag External</string>
      <key>Criterion</key><string>From contains @example.com</string>
      <key>Action</key><string>Mark Flagged</string>
    </dict>
  </array>
</dict>
</plist>"#;
        std::fs::write(&plist_path, plist_xml).unwrap();

        let spec = text_spec(
            "macos.mail.rules",
            "Mail rules plist content",
            "",
            vec![plist_path.display().to_string()],
        );
        let rows = parse_spec(&spec);
        assert!(
            rows.iter()
                .any(|r| r.detail.as_deref() == Some("plist_semantic_mail_rules")),
            "expected semantic mail rules summary record"
        );
        assert!(
            rows.iter().any(|r| r.primary.contains("mail.rules=")),
            "expected mail rules semantic primary"
        );
    }

    #[test]
    fn adds_mail_accounts_semantic_record() {
        let dir = tempdir().unwrap();
        let plist_path = dir.path().join("Accounts.plist");
        let plist_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>MailAccounts</key>
  <array>
    <dict>
      <key>EmailAddress</key><string>investigator@example.com</string>
      <key>Hostname</key><string>imap.example.com</string>
      <key>Username</key><string>investigator</string>
    </dict>
  </array>
</dict>
</plist>"#;
        std::fs::write(&plist_path, plist_xml).unwrap();

        let spec = text_spec(
            "macos.mail.accounts",
            "Mail account settings",
            "",
            vec![plist_path.display().to_string()],
        );
        let rows = parse_spec(&spec);
        assert!(
            rows.iter()
                .any(|r| r.detail.as_deref() == Some("plist_semantic_mail_accounts")),
            "expected semantic mail accounts summary record"
        );
        assert!(
            rows.iter().any(|r| r.primary.contains("mail.accounts=")),
            "expected mail accounts semantic primary"
        );
    }

    #[test]
    fn adds_loginwindow_semantic_record() {
        let dir = tempdir().unwrap();
        let plist_path = dir.path().join("com.apple.loginwindow.plist");
        let plist_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>lastUserName</key><string>analyst</string>
  <key>autoLoginUser</key><string>analyst</string>
  <key>SHOWFULLNAME</key><true/>
</dict>
</plist>"#;
        std::fs::write(&plist_path, plist_xml).unwrap();

        let spec = text_spec(
            "macos.user.loginwindow",
            "LoginWindow prefs and recent users",
            "",
            vec![plist_path.display().to_string()],
        );
        let rows = parse_spec(&spec);
        assert!(
            rows.iter()
                .any(|r| r.detail.as_deref() == Some("plist_semantic_loginwindow")),
            "expected semantic loginwindow summary record"
        );
        assert!(
            rows.iter()
                .any(|r| r.primary.contains("loginwindow.items=")),
            "expected loginwindow semantic primary"
        );
    }

    #[test]
    fn adds_network_preferences_semantic_record() {
        let dir = tempdir().unwrap();
        let plist_path = dir.path().join("network-preferences.plist");
        let plist_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Proxies</key>
  <dict>
    <key>HTTPEnable</key><integer>1</integer>
    <key>HTTPProxy</key><string>proxy.local</string>
    <key>HTTPPort</key><integer>8080</integer>
  </dict>
  <key>VPN</key>
  <dict>
    <key>ServerAddress</key><string>vpn.example.com</string>
  </dict>
</dict>
</plist>"#;
        std::fs::write(&plist_path, plist_xml).unwrap();

        let spec = text_spec(
            "macos.network.proxies",
            "Proxy config entries",
            "",
            vec![plist_path.display().to_string()],
        );
        let rows = parse_spec(&spec);
        assert!(
            rows.iter()
                .any(|r| { r.detail.as_deref() == Some("plist_semantic_network_preferences") }),
            "expected semantic network preferences summary record"
        );
        assert!(
            rows.iter()
                .any(|r| r.primary.contains("network.preferences=")),
            "expected network preferences semantic primary"
        );
    }

    #[test]
    fn adds_system_version_semantic_record() {
        let dir = tempdir().unwrap();
        let plist_path = dir.path().join("SystemVersion.plist");
        let plist_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>ProductName</key><string>macOS</string>
  <key>ProductVersion</key><string>14.4</string>
  <key>ProductBuildVersion</key><string>23E214</string>
</dict>
</plist>"#;
        std::fs::write(&plist_path, plist_xml).unwrap();

        let spec = text_spec(
            "macos.system.version",
            "SystemVersion plist",
            "",
            vec![plist_path.display().to_string()],
        );
        let rows = parse_spec(&spec);
        assert!(
            rows.iter()
                .any(|r| r.detail.as_deref() == Some("plist_semantic_system_version")),
            "expected semantic system version record"
        );
        assert!(
            rows.iter()
                .any(|r| r.primary.contains("system.version=macOS 14.4")),
            "expected system version semantic primary"
        );
    }

    #[test]
    fn adds_time_machine_semantic_record() {
        let dir = tempdir().unwrap();
        let plist_path = dir.path().join("com.apple.TimeMachine.plist");
        let plist_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Destinations</key>
  <array>
    <dict>
      <key>BackupAlias</key><string>TM-Backup</string>
      <key>LastConnected</key><date>2026-03-08T08:00:00Z</date>
    </dict>
  </array>
</dict>
</plist>"#;
        std::fs::write(&plist_path, plist_xml).unwrap();

        let spec = text_spec(
            "macos.time_machine.history",
            "Time Machine backup history",
            "",
            vec![plist_path.display().to_string()],
        );
        let rows = parse_spec(&spec);
        assert!(
            rows.iter()
                .any(|r| r.detail.as_deref() == Some("plist_semantic_time_machine")),
            "expected semantic time machine record"
        );
        assert!(
            rows.iter()
                .any(|r| r.primary.contains("time_machine.items=")),
            "expected time machine semantic primary"
        );
    }

    #[test]
    fn adds_network_interfaces_semantic_record() {
        let dir = tempdir().unwrap();
        let plist_path = dir.path().join("NetworkInterfaces.plist");
        let plist_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Interfaces</key>
  <array>
    <dict>
      <key>BSD Name</key><string>en0</string>
      <key>SCNetworkInterfaceType</key><string>Ethernet</string>
      <key>SCNetworkInterfaceHardware</key><string>Ethernet</string>
    </dict>
  </array>
</dict>
</plist>"#;
        std::fs::write(&plist_path, plist_xml).unwrap();

        let spec = text_spec(
            "macos.network.interfaces",
            "Network interface plist",
            "",
            vec![plist_path.display().to_string()],
        );
        let rows = parse_spec(&spec);
        assert!(
            rows.iter()
                .any(|r| r.detail.as_deref() == Some("plist_semantic_network_interfaces")),
            "expected semantic network interfaces record"
        );
        assert!(
            rows.iter()
                .any(|r| r.primary.contains("network.interfaces=")),
            "expected network interfaces semantic primary"
        );
    }

    #[test]
    fn adds_wifi_known_networks_semantic_record() {
        let dir = tempdir().unwrap();
        let plist_path = dir.path().join("airport.preferences.plist");
        let plist_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>KnownNetworks</key>
  <dict>
    <key>wifi.ssid.OfficeWiFi</key>
    <dict>
      <key>SSIDString</key><string>OfficeWiFi</string>
      <key>SecurityType</key><string>WPA2</string>
      <key>LastConnected</key><date>2026-03-08T09:00:00Z</date>
    </dict>
  </dict>
</dict>
</plist>"#;
        std::fs::write(&plist_path, plist_xml).unwrap();

        let spec = text_spec(
            "macos.wifi.known_networks",
            "Known Wi-Fi networks plist",
            "",
            vec![plist_path.display().to_string()],
        );
        let rows = parse_spec(&spec);
        assert!(
            rows.iter()
                .any(|r| { r.detail.as_deref() == Some("plist_semantic_wifi_known_networks") }),
            "expected semantic known wifi networks record"
        );
        assert!(
            rows.iter()
                .any(|r| r.primary.contains("wifi.known_networks=")),
            "expected known wifi semantic primary"
        );
    }

    #[test]
    fn adds_installhistory_semantic_record() {
        let dir = tempdir().unwrap();
        let plist_path = dir.path().join("InstallHistory.plist");
        let plist_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array>
  <dict>
    <key>displayName</key><string>Xcode</string>
    <key>displayVersion</key><string>15.4</string>
    <key>processName</key><string>Installer</string>
    <key>date</key><date>2026-03-08T12:00:00Z</date>
  </dict>
</array>
</plist>"#;
        std::fs::write(&plist_path, plist_xml).unwrap();

        let spec = text_spec(
            "macos.installhistory",
            "InstallHistory.plist software install records",
            "",
            vec![plist_path.display().to_string()],
        );
        let rows = parse_spec(&spec);
        assert!(
            rows.iter()
                .any(|r| r.detail.as_deref() == Some("plist_semantic_installhistory")),
            "expected semantic install history record"
        );
        assert!(
            rows.iter()
                .any(|r| r.primary.contains("installhistory.items=")),
            "expected installhistory semantic primary"
        );
    }

    #[test]
    fn adds_bluetooth_paired_semantic_record() {
        let dir = tempdir().unwrap();
        let plist_path = dir.path().join("Bluetooth.plist");
        let plist_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>DeviceCache</key>
  <dict>
    <key>AA-BB-CC-DD-EE-FF</key>
    <dict>
      <key>Name</key><string>Magic Keyboard</string>
      <key>Address</key><string>AA-BB-CC-DD-EE-FF</string>
      <key>LastSeenTime</key><date>2026-03-08T13:00:00Z</date>
    </dict>
  </dict>
</dict>
</plist>"#;
        std::fs::write(&plist_path, plist_xml).unwrap();

        let spec = text_spec(
            "macos.bluetooth.paired_devices",
            "Bluetooth paired devices plist",
            "",
            vec![plist_path.display().to_string()],
        );
        let rows = parse_spec(&spec);
        assert!(
            rows.iter()
                .any(|r| { r.detail.as_deref() == Some("plist_semantic_bluetooth_paired") }),
            "expected semantic bluetooth paired record"
        );
        assert!(
            rows.iter()
                .any(|r| r.primary.contains("bluetooth.paired_devices=")),
            "expected bluetooth semantic primary"
        );
    }

    #[test]
    fn adds_airdrop_semantic_record() {
        let dir = tempdir().unwrap();
        let plist_path = dir.path().join("airdrop.plist");
        let plist_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>AirDropPeers</key>
  <array>
    <dict>
      <key>DeviceName</key><string>MacBook-Pro</string>
      <key>LastSeen</key><date>2026-03-08T14:00:00Z</date>
      <key>Receiver</key><string>user@example.com</string>
    </dict>
  </array>
</dict>
</plist>"#;
        std::fs::write(&plist_path, plist_xml).unwrap();

        let spec = text_spec(
            "macos.network.airdrop",
            "AirDrop interaction traces",
            "",
            vec![plist_path.display().to_string()],
        );
        let rows = parse_spec(&spec);
        assert!(
            rows.iter()
                .any(|r| r.detail.as_deref() == Some("plist_semantic_airdrop")),
            "expected semantic airdrop record"
        );
        assert!(
            rows.iter()
                .any(|r| r.primary.contains("network.airdrop.items=")),
            "expected airdrop semantic primary"
        );
    }

    #[test]
    fn adds_airplay_semantic_record() {
        let dir = tempdir().unwrap();
        let plist_path = dir.path().join("airplay.plist");
        let plist_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>AirPlayDevices</key>
  <array>
    <dict>
      <key>Name</key><string>Living Room TV</string>
      <key>RouteUID</key><string>route-123</string>
      <key>LastConnected</key><date>2026-03-08T15:00:00Z</date>
    </dict>
  </array>
</dict>
</plist>"#;
        std::fs::write(&plist_path, plist_xml).unwrap();

        let spec = text_spec(
            "macos.network.airplay",
            "AirPlay target history",
            "",
            vec![plist_path.display().to_string()],
        );
        let rows = parse_spec(&spec);
        assert!(
            rows.iter()
                .any(|r| r.detail.as_deref() == Some("plist_semantic_airplay")),
            "expected semantic airplay record"
        );
        assert!(
            rows.iter()
                .any(|r| r.primary.contains("network.airplay.items=")),
            "expected airplay semantic primary"
        );
    }

    #[test]
    fn adds_hotspot_semantic_record() {
        let dir = tempdir().unwrap();
        let plist_path = dir.path().join("hotspot.plist");
        let plist_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PersonalHotspot</key>
  <dict>
    <key>Enabled</key><true/>
    <key>SSID</key><string>InvestigatorHotspot</string>
    <key>LastUsed</key><date>2026-03-08T16:00:00Z</date>
  </dict>
</dict>
</plist>"#;
        std::fs::write(&plist_path, plist_xml).unwrap();

        let spec = text_spec(
            "macos.network.hotspot",
            "Personal hotspot state/history",
            "",
            vec![plist_path.display().to_string()],
        );
        let rows = parse_spec(&spec);
        assert!(
            rows.iter()
                .any(|r| r.detail.as_deref() == Some("plist_semantic_hotspot")),
            "expected semantic hotspot record"
        );
        assert!(
            rows.iter()
                .any(|r| r.primary.contains("network.hotspot.items=")),
            "expected hotspot semantic primary"
        );
    }

    #[test]
    fn adds_private_relay_semantic_record() {
        let dir = tempdir().unwrap();
        let plist_path = dir.path().join("private_relay.plist");
        let plist_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>iCloudPrivateRelay</key>
  <dict>
    <key>Enabled</key><true/>
    <key>Status</key><string>active</string>
    <key>LastUpdated</key><date>2026-03-08T16:30:00Z</date>
  </dict>
</dict>
</plist>"#;
        std::fs::write(&plist_path, plist_xml).unwrap();

        let spec = text_spec(
            "macos.network.icloud_private_relay",
            "iCloud private relay state",
            "",
            vec![plist_path.display().to_string()],
        );
        let rows = parse_spec(&spec);
        assert!(
            rows.iter()
                .any(|r| r.detail.as_deref() == Some("plist_semantic_private_relay")),
            "expected semantic private relay record"
        );
        assert!(
            rows.iter()
                .any(|r| r.primary.contains("network.icloud_private_relay.items=")),
            "expected private relay semantic primary"
        );
    }

    #[test]
    fn adds_location_services_semantic_record() {
        let dir = tempdir().unwrap();
        let plist_path = dir.path().join("location_services.plist");
        let plist_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>LocationServicesEnabled</key><true/>
  <key>Applications</key>
  <dict>
    <key>com.apple.Maps</key>
    <dict>
      <key>Authorized</key><true/>
      <key>LastUseDate</key><date>2026-03-08T17:00:00Z</date>
    </dict>
  </dict>
</dict>
</plist>"#;
        std::fs::write(&plist_path, plist_xml).unwrap();

        let spec = text_spec(
            "macos.network.location_services",
            "Location services network context",
            "",
            vec![plist_path.display().to_string()],
        );
        let rows = parse_spec(&spec);
        assert!(
            rows.iter()
                .any(|r| { r.detail.as_deref() == Some("plist_semantic_location_services") }),
            "expected semantic location services record"
        );
        assert!(
            rows.iter()
                .any(|r| r.primary.contains("network.location_services.items=")),
            "expected location services semantic primary"
        );
    }

    #[test]
    fn adds_print_recent_jobs_semantic_record() {
        let dir = tempdir().unwrap();
        let plist_path = dir.path().join("print_jobs.plist");
        let plist_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>RecentPrintJobs</key>
  <array>
    <dict>
      <key>DocumentName</key><string>incident_report.pdf</string>
      <key>PrinterName</key><string>OfficeJet</string>
      <key>LastPrinted</key><date>2026-03-08T17:30:00Z</date>
    </dict>
  </array>
</dict>
</plist>"#;
        std::fs::write(&plist_path, plist_xml).unwrap();

        let spec = text_spec(
            "macos.print.recent_jobs",
            "Recent print job traces",
            "",
            vec![plist_path.display().to_string()],
        );
        let rows = parse_spec(&spec);
        assert!(
            rows.iter()
                .any(|r| { r.detail.as_deref() == Some("plist_semantic_print_recent_jobs") }),
            "expected semantic print recent jobs record"
        );
        assert!(
            rows.iter()
                .any(|r| r.primary.contains("print.recent_jobs.items=")),
            "expected print jobs semantic primary"
        );
    }

    #[test]
    fn adds_finder_tags_semantic_record() {
        let dir = tempdir().unwrap();
        let plist_path = dir.path().join("finder_tags.plist");
        let plist_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>FavoriteTags</key>
  <array>
    <dict>
      <key>Name</key><string>Evidence</string>
      <key>Label</key><string>Green</string>
      <key>RecentItem</key><string>/Users/test/Documents/case.txt</string>
    </dict>
  </array>
</dict>
</plist>"#;
        std::fs::write(&plist_path, plist_xml).unwrap();

        let spec = text_spec(
            "macos.finder.tags",
            "Finder tag metadata",
            "",
            vec![plist_path.display().to_string()],
        );
        let rows = parse_spec(&spec);
        assert!(
            rows.iter()
                .any(|r| r.detail.as_deref() == Some("plist_semantic_finder_tags")),
            "expected semantic finder tags record"
        );
        assert!(
            rows.iter()
                .any(|r| r.primary.contains("finder.tags.items=")),
            "expected finder tags semantic primary"
        );
    }

    #[test]
    fn adds_saved_state_windows_semantic_record() {
        let dir = tempdir().unwrap();
        let plist_path = dir.path().join("window_state.plist");
        let plist_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>WindowState</key>
  <dict>
    <key>WindowTitle</key><string>Safari</string>
    <key>WindowFrame</key><string>{{100, 100}, {1200, 900}}</string>
    <key>LastSession</key><date>2026-03-08T18:00:00Z</date>
  </dict>
</dict>
</plist>"#;
        std::fs::write(&plist_path, plist_xml).unwrap();

        let spec = text_spec(
            "macos.saved_state.windows",
            "NSWindow saved state artifacts",
            "",
            vec![plist_path.display().to_string()],
        );
        let rows = parse_spec(&spec);
        assert!(
            rows.iter()
                .any(|r| { r.detail.as_deref() == Some("plist_semantic_saved_state_windows") }),
            "expected semantic saved state windows record"
        );
        assert!(
            rows.iter()
                .any(|r| r.primary.contains("saved_state.windows.items=")),
            "expected saved state windows semantic primary"
        );
    }
}
