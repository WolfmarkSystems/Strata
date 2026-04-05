use crate::context::ForgeContext;
use crate::history::Conversation;
use crate::knowledge::KnowledgeBase;
use crate::llm::LlmClient;
use crate::settings::ForgeSettings;
use std::sync::Mutex;

/// Application-wide shared state managed by Tauri.
pub struct ForgeState {
    /// LLM client instance (configurable).
    pub llm: Mutex<LlmClient>,
    /// Current evidence context (set by Tree or manual entry).
    pub context: Mutex<ForgeContext>,
    /// Active conversation.
    pub conversation: Mutex<Option<Conversation>>,
    /// Application settings.
    pub settings: Mutex<ForgeSettings>,
    /// Local DFIR knowledge base.
    pub kb: KnowledgeBase,
}

impl ForgeState {
    pub fn new(settings: ForgeSettings) -> Self {
        let llm = LlmClient::new(
            &settings.llm_base_url,
            &settings.llm_model,
            settings.llm_timeout_secs,
        );
        let kb = KnowledgeBase::load();
        let (tools, techs, arts, paths, actors) = kb.stats();
        println!(
            "[FORGE] Knowledge base loaded: {} tools, {} techniques, {} artifacts, {} paths, {} actors",
            tools, techs, arts, paths, actors
        );

        Self {
            llm: Mutex::new(llm),
            context: Mutex::new(ForgeContext::default()),
            conversation: Mutex::new(None),
            settings: Mutex::new(settings),
            kb,
        }
    }
}
