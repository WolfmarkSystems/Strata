pub use crate::parsers;

use crate::virtualization::VfsEntry;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParserError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Database error: {0}")]
    Database(String),
    #[error("Parse error: {0}")]
    Parse(String),
    #[error("VFS error: {0}")]
    Vfs(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ParsedArtifact {
    pub timestamp: Option<i64>,
    pub artifact_type: String,
    pub description: String,
    pub source_path: String,
    pub json_data: serde_json::Value,
}

impl From<strata_plugin_sdk::Artifact> for ParsedArtifact {
    fn from(artifact: strata_plugin_sdk::Artifact) -> Self {
        ParsedArtifact {
            timestamp: artifact.timestamp.map(|ts| ts as i64),
            artifact_type: artifact.category,
            description: artifact.source.clone(),
            source_path: artifact.source,
            json_data: serde_json::json!(artifact.data),
        }
    }
}

pub trait ArtifactParser: Send + Sync {
    fn name(&self) -> &str;
    fn artifact_type(&self) -> &str;
    fn target_patterns(&self) -> Vec<&str>;

    fn parse_file(&self, path: &Path, data: &[u8]) -> Result<Vec<ParsedArtifact>, ParserError>;
}

pub struct ParserRegistry {
    parsers: Vec<Box<dyn ArtifactParser>>,
}

impl ParserRegistry {
    pub fn new() -> Self {
        Self {
            parsers: Vec::new(),
        }
    }

    pub fn register(&mut self, parser: Box<dyn ArtifactParser>) {
        self.parsers.push(parser);
    }

    pub fn register_default_parsers(&mut self) {
        self.register(Box::new(crate::parsers::registry::RegistryParser::new()));
        self.register(Box::new(crate::parsers::prefetch::PrefetchParser::new()));
        self.register(Box::new(crate::parsers::shellbags::ShellbagsParser::new()));
        self.register(Box::new(crate::parsers::evtx::EvtxParser::new()));

        self.register(Box::new(
            crate::parsers::browser::BrowserParser::for_chrome(),
        ));
        self.register(Box::new(crate::parsers::browser::BrowserParser::for_edge()));
        self.register(Box::new(
            crate::parsers::browser::BrowserParser::for_firefox(),
        ));
        self.register(Box::new(crate::parsers::browser::BrowserParser::for_brave()));
        self.register(Box::new(crate::parsers::browser::BrowserParser::for_ie()));

        self.register(Box::new(crate::parsers::jumplist::JumpListParser::new()));
        self.register(Box::new(crate::parsers::lnk::LnkParser::new()));
        self.register(Box::new(crate::parsers::recentdocs::RecentDocsParser::new()));

        self.register(Box::new(crate::parsers::srum::SrumParser::new()));
        self.register(Box::new(crate::parsers::amcache::AmcacheParser::new()));

        self.register(Box::new(crate::parsers::recyclebin::RecycleBinParser::new()));
        self.register(Box::new(crate::parsers::recyclebin::UsnJournalParser::new()));

        self.register(Box::new(crate::parsers::outlook::OutlookParser::for_pst()));
        self.register(Box::new(crate::parsers::outlook::OutlookParser::for_ost()));
        self.register(Box::new(crate::parsers::onedrive::OneDriveParser::new()));
        self.register(Box::new(crate::parsers::teams::TeamsParser::new()));
        self.register(Box::new(crate::parsers::skype::SkypeParser::new()));
        self.register(Box::new(
            crate::parsers::windows_search::WindowsSearchParser::new(),
        ));

        self.register(Box::new(
            crate::parsers::macos::launchd::LaunchdParser::for_agent(),
        ));
        self.register(Box::new(
            crate::parsers::macos::launchd::LaunchdParser::for_daemon(),
        ));
        self.register(Box::new(crate::parsers::macos::tcc::MacosTccParser::new()));
        self.register(Box::new(
            crate::parsers::macos::quarantine::MacosQuarantineParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::macos::alias_bookmark::MacosAliasBookmarkParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::macos::apfs_snapshot_diff::ApfsSnapshotDiffParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::macos::unified_logs::UnifiedLogsParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::macos::spotlight::SpotlightParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::macos::spotlight_carver::SpotlightCarver::new(),
        ));
        self.register(Box::new(
            crate::parsers::macos::timemachine::TimeMachineParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::macos::safari::SafariParser::for_history(),
        ));
        self.register(Box::new(
            crate::parsers::macos::safari::SafariParser::for_cookies(),
        ));
        self.register(Box::new(
            crate::parsers::macos::safari::SafariParser::for_downloads(),
        ));
        self.register(Box::new(
            crate::parsers::macos::imessage::ImessageParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::macos::keychain::KeychainParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::macos::notes::MacosNotesParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::macos::calendar::MacosCalendarParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::macos::contacts::MacosContactsParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::macos::reminders::MacosRemindersParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::macos::safari_cloud_tabs::SafariCloudTabsParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::macos::safari_cache::SafariCacheParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::macos::screentime::MacosScreentimeParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::macos::mdm_audit::MacosMdmParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::macos::firewall::MacosFirewallParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::macos::networking_audit::MacosNetworkingAudit::new(),
        ));
        self.register(Box::new(
            crate::parsers::macos::sip_audit::MacosSipAuditParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::macos::startup_timeline::MacosStartupParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::macos::homekit::MacosHomeKitParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::macos::photos::MacosPhotosParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::macos::install_history::MacosInstallHistoryParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::macos::fsevents::MacosFseventsParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::macos::browser_extensions::BrowserExtensionParser::new(),
        ));
        self.register(Box::new(crate::parsers::macos::cron::MacosCronParser::new()));
        self.register(Box::new(
            crate::parsers::macos::knowledgec::MacosKnowledgecParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::macos::cloud_storage::MacosCloudStorageParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::macos::bluetooth_audit::MacosBluetoothParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::macos::network_shares::MacosNetworkShareParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::macos::power_management::PowerManagementParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::macos::filevault::MacosFileVaultParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::macos::networking::MacosNetworkingParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::macos::recent_items::MacosRecentItemsParser::new(),
        ));
        self.register(Box::new(crate::parsers::macos::apps::MacosAppsParser::new()));
        self.register(Box::new(
            crate::parsers::macos::shell_history::MacosShellHistoryParser::new(),
        ));
        self.register(Box::new(crate::parsers::macos::auth::MacosAuthParser::new()));
        self.register(Box::new(
            crate::parsers::macos::app_usage::MacosAppUsageParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::macos::system_config::MacosSystemConfigParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::macos::quicklook::MacosQuickLookParser::new(),
        ));

        self.register(Box::new(crate::parsers::ios::backup::IosBackupParser::new()));
        self.register(Box::new(crate::parsers::ios::biome::BiomeParser::new()));
        self.register(Box::new(
            crate::parsers::ios::call_history::IosCallHistoryParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::ios::whatsapp::WhatsAppParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::ios::ios_imessage::IosImessageParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::ios::knowledgec::KnowledgecParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::ios::interactionc::InteractioncParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::ios::powerlog::PowerlogParser::new(),
        ));
        self.register(Box::new(crate::parsers::ios::ffs::CheckrainFfsParser::new()));
        self.register(Box::new(
            crate::parsers::ios::ios_safari::IosSafariParser::new(),
        ));
        self.register(Box::new(crate::parsers::ios::photos::PhotosParser::new()));
        self.register(Box::new(
            crate::parsers::ios::location::LocationParser::new(),
        ));
        self.register(Box::new(crate::parsers::ios::health::HealthParser::new()));
        self.register(Box::new(crate::parsers::ios::graykey::GraykeyParser::new()));
        self.register(Box::new(
            crate::parsers::ios::cellebrite::CellebriteParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::ios::magnet_axiom::AxiomParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::ios::screentime::IosScreenTimeParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::ios::app_usage::IosAppUsageParser::new(),
        ));
        self.register(Box::new(crate::parsers::ios::wallet::IosWalletParser::new()));
        self.register(Box::new(
            crate::parsers::ios::wallet::IosAppGroupParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::ios::reminders::IosRemindersParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::ios::keychain_ios::IosKeychainParser::new(),
        ));

        self.register(Box::new(
            crate::parsers::linux::journal::JournalParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::linux::ir_artifacts::LinuxIrArtifactsParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::linux::bash_history::BashHistoryParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::linux::zsh_history::ZshHistoryParser::new(),
        ));
        self.register(Box::new(crate::parsers::linux::cron::CronParser::new()));
        self.register(Box::new(
            crate::parsers::linux::apt_logs::AptLogsParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::linux::linux_browser::LinuxBrowserParser::for_firefox(),
        ));
        self.register(Box::new(
            crate::parsers::linux::linux_browser::LinuxBrowserParser::for_chrome(),
        ));
        self.register(Box::new(crate::parsers::linux::varlog::VarLogParser::new()));
        self.register(Box::new(
            crate::parsers::linux::packages::PackagesParser::new(),
        ));

        self.register(Box::new(
            crate::parsers::cloud::gdrive::GoogleDriveParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::cloud::dropbox::DropboxParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::cloud::icloud::IcloudSyncParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::cloud::google_takeout::GoogleTakeoutParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::cloud::office365::Office365Parser::new(),
        ));
        self.register(Box::new(
            crate::parsers::cloud::graph_api::GraphApiParser::new(),
        ));

        self.register(Box::new(crate::parsers::email::email::EmailParser::new()));
        self.register(Box::new(
            crate::parsers::email::outlook_full::OutlookFullParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::email::outlook_deep::OutlookDeepParser::new(),
        ));
        self.register(Box::new(crate::parsers::email::gmail::GmailParser::new()));
        self.register(Box::new(
            crate::parsers::email::thunderbird::ThunderbirdParser::new(),
        ));

        self.register(Box::new(crate::parsers::chat::discord::DiscordParser::new()));
        self.register(Box::new(crate::parsers::chat::slack::SlackParser::new()));
        self.register(Box::new(
            crate::parsers::chat::telegram::TelegramParser::new(),
        ));

        self.register(Box::new(
            crate::parsers::mobile::android::AndroidParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::mobile::android_full::AndroidFullParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::mobile::usagestats::UsageStatsParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::mobile::samsung::SamsungParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::mobile::keystore::AndroidKeystoreParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::mobile::third_party_apps::ThirdPartyMobileAppsParser::new(),
        ));
        self.register(Box::new(crate::parsers::mobile::signal::SignalParser::new()));
        self.register(Box::new(
            crate::parsers::mobile::whatsapp_full::WhatsAppFullParser::new(),
        ));

        self.register(Box::new(
            crate::parsers::network::network::NetworkParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::network::cloud_audit::CloudAuditParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::network::malware::MalwareParser::new(),
        ));

        self.register(Box::new(
            crate::parsers::network_deep::aws_deep::AwsDeepParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::network_deep::azure_deep::AzureDeepParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::network_deep::google_workspace::GoogleWorkspaceParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::network_deep::pcap_parser::PcapParser::new(),
        ));

        self.register(Box::new(
            crate::parsers::acquisition::phone_detector::PhoneImageDetector::new(),
        ));
        self.register(Box::new(
            crate::parsers::acquisition::acquisition::AcquisitionParser::new(),
        ));

        self.register(Box::new(
            crate::parsers::analysis::steganography::SteganographyParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::analysis::ransomware::RansomwareParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::analysis::advanced_search::AdvancedSearchParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::analysis::ai_triage::AiTriageParser::new(),
        ));

        // === New parsers (v0.3.1) ===

        // Windows ActivitiesCache (Windows Timeline)
        self.register(Box::new(
            crate::parsers::activities_cache::ActivitiesCacheParser::new(),
        ));

        // Windows Push Notification Database
        self.register(Box::new(
            crate::parsers::windows_notifications::WindowsNotificationsParser::new(),
        ));

        // Windows Thumbcache
        self.register(Box::new(
            crate::parsers::thumbcache::ThumbcacheParser::new(),
        ));

        // MFT Timestomp Detection
        self.register(Box::new(
            crate::parsers::mft_timestomp::MftTimestompParser::new(),
        ));

        // RDP Artifact Correlation
        self.register(Box::new(
            crate::parsers::rdp_artifacts::RdpArtifactsParser::new(),
        ));

        // SSH Artifacts (Linux/macOS)
        self.register(Box::new(
            crate::parsers::linux::ssh_artifacts::SshArtifactsParser::new(),
        ));

        // Apple Mail (.emlx)
        self.register(Box::new(
            crate::parsers::email::apple_mail::AppleMailParser::new(),
        ));

        // === Batch 2 parsers (v0.3.2) ===

        // Facebook Messenger
        self.register(Box::new(
            crate::parsers::facebook_messenger::FacebookMessengerParser::new(),
        ));

        // Browser Autofill/Passwords
        self.register(Box::new(
            crate::parsers::browser_autofill::BrowserAutofillParser::new(),
        ));

        // Docker/Container Forensics
        self.register(Box::new(
            crate::parsers::docker_forensics::DockerForensicsParser::new(),
        ));

        // UserAssist ROT13
        self.register(Box::new(
            crate::parsers::userassist::UserAssistParser::new(),
        ));

        // Windows Scheduled Tasks XML
        self.register(Box::new(
            crate::parsers::scheduled_tasks::ScheduledTasksParser::new(),
        ));

        // BITS Transfer Parser
        self.register(Box::new(
            crate::parsers::bits_parser::BitsParser::new(),
        ));

        // Browser IndexedDB/LocalStorage
        self.register(Box::new(
            crate::parsers::browser_storage::BrowserStorageParser::new(),
        ));

        // Volatility Output Import
        self.register(Box::new(
            crate::parsers::volatility_import::VolatilityImportParser::new(),
        ));

        // macOS CoreAnalytics
        self.register(Box::new(
            crate::parsers::macos::coreanalytics::CoreAnalyticsParser::new(),
        ));

        // ADB Backup Parser
        self.register(Box::new(
            crate::parsers::adb_backup::AdbBackupParser::new(),
        ));

        // Tor Browser Artifacts
        self.register(Box::new(
            crate::parsers::tor_browser::TorBrowserParser::new(),
        ));

        // VPN Client Artifacts
        self.register(Box::new(
            crate::parsers::vpn_artifacts::VpnArtifactsParser::new(),
        ));

        // Systemd Unit Files (Linux persistence)
        self.register(Box::new(
            crate::parsers::linux::systemd_units::SystemdUnitParser::new(),
        ));

        // ESE Database Parser
        self.register(Box::new(
            crate::parsers::ese_parser::EseParser::new(),
        ));

        // Volume Shadow Copy Parser
        self.register(Box::new(
            crate::parsers::vss_extraction::VssExtractionParser::new(),
        ));

        // Cross-Source Execution Correlation Engine
        self.register(Box::new(
            crate::parsers::execution_correlation::ExecutionCorrelationParser::new(),
        ));

        // === macOS expansion (v1.5.0) ===
        self.register(Box::new(
            crate::parsers::macos::safari_full::SafariFullParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::macos::chrome_macos::ChromeMacOsParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::macos::firefox_macos::FirefoxMacOsParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::macos::icloud_drive::ICloudDriveParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::macos::spotlight_metadata::SpotlightMetadataParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::macos::dock::MacosDockParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::macos::document_revisions::MacosDocumentRevisionsParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::macos::screentime_full::MacosScreentimeFullParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::macos::terminal_history::MacosTerminalHistoryParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::macos::ssh_macos::MacosSshParser::new(),
        ));

        // === UFDR ingestion (v1.5.0) ===
        self.register(Box::new(crate::parsers::ufdr::UfdrParser::new()));

        // === Browser forensic parsers (v1.5.0) ===
        self.register(Box::new(
            crate::parsers::browser_forensic::ChromiumForensicParser::chrome(),
        ));
        self.register(Box::new(
            crate::parsers::browser_forensic::ChromiumForensicParser::edge(),
        ));
        self.register(Box::new(
            crate::parsers::browser_forensic::ChromiumForensicParser::brave(),
        ));
        self.register(Box::new(
            crate::parsers::browser_forensic::FirefoxForensicParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::browser_forensic::SafariForensicParser::new(),
        ));

        // Memory forensics
        self.register(Box::new(
            crate::parsers::memory::HiberfilParser::new(),
        ));
        self.register(Box::new(
            crate::parsers::memory::PagefileParser::new(),
        ));
    }

    pub fn parsers(&self) -> &[Box<dyn ArtifactParser>] {
        &self.parsers
    }

    pub fn find_files_for_parser(
        &self,
        parser: &dyn ArtifactParser,
        entries: &[VfsEntry],
    ) -> Vec<PathBuf> {
        let patterns = parser.target_patterns();
        let mut matches = Vec::new();

        for entry in entries {
            if entry.is_dir {
                continue;
            }

            let name = entry.name.to_lowercase();
            let full_path = entry.path.to_string_lossy().to_lowercase();

            for pattern in &patterns {
                let pattern_lower = pattern.to_lowercase();
                if let Some(suffix) = pattern_lower.strip_prefix('*') {
                    if name.ends_with(suffix) || full_path.ends_with(suffix) {
                        matches.push(entry.path.clone());
                        break;
                    }
                } else if name == pattern_lower
                    || name.contains(&pattern_lower)
                    || full_path.contains(&pattern_lower)
                {
                    matches.push(entry.path.clone());
                    break;
                }
            }
        }

        matches
    }

    pub fn parse_parallel(
        &self,
        entries: &[VfsEntry],
        read_file_fn: impl Fn(&Path) -> Result<Vec<u8>, ParserError> + Sync + Send,
    ) -> Vec<ParsedArtifact> {
        #[cfg(feature = "parallel")]
        {
            use rayon::prelude::*;
            self.parsers
                .par_iter()
                .flat_map(|parser| {
                    let matches = self.find_files_for_parser(parser.as_ref(), entries);
                    let mut artifacts = Vec::new();
                    for path in matches {
                        if let Ok(data) = read_file_fn(&path) {
                            if let Ok(mut result) = parser.parse_file(&path, &data) {
                                artifacts.append(&mut result);
                            }
                        }
                    }
                    artifacts
                })
                .collect()
        }
        #[cfg(not(feature = "parallel"))]
        {
            let mut all_artifacts = Vec::new();
            for parser in &self.parsers {
                let matches = self.find_files_for_parser(parser.as_ref(), entries);
                for path in matches {
                    if let Ok(data) = read_file_fn(&path) {
                        if let Ok(mut result) = parser.parse_file(&path, &data) {
                            all_artifacts.append(&mut result);
                        }
                    }
                }
            }
            all_artifacts
        }
    }
}

impl Default for ParserRegistry {
    fn default() -> Self {
        Self::new()
    }
}
