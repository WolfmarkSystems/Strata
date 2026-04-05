use crate::context::ForgeContext;
use crate::forge_state::ForgeState;
use crate::history::{Conversation, ConversationSummary};
use crate::ioc;
use crate::llm::ChatMessage;
use crate::prompt;
use crate::settings::ForgeSettings;
use tauri::Emitter;

// ─── Forge Query (non-streaming) ─────────────────────────────────

#[tauri::command]
pub async fn forge_query(
    query: String,
    context: Option<ForgeContext>,
    state: tauri::State<'_, ForgeState>,
) -> Result<String, String> {
    let ctx = match context {
        Some(c) => c,
        None => {
            let guard = state
                .context
                .lock()
                .map_err(|e| format!("State lock failed: {}", e))?;
            guard.clone()
        }
    };

    let system_prompt = prompt::build_system_prompt(&ctx);

    let messages = vec![ChatMessage {
        role: "user".to_string(),
        content: query,
    }];

    let llm = state
        .llm
        .lock()
        .map_err(|e| format!("LLM lock failed: {}", e))?
        .clone();

    let response = llm
        .generate(&system_prompt, &messages)
        .await
        .map_err(|e| e.to_string())?;

    Ok(response.content)
}

// ─── Forge Streaming Query ───────────────────────────────────────

#[tauri::command]
pub async fn forge_stream_query(
    query: String,
    history: Vec<ChatMessage>,
    context: Option<ForgeContext>,
    window: tauri::Window,
    state: tauri::State<'_, ForgeState>,
) -> Result<(), String> {
    let ctx = match context {
        Some(c) => c,
        None => {
            let guard = state
                .context
                .lock()
                .map_err(|e| format!("State lock failed: {}", e))?;
            guard.clone()
        }
    };

    let system_prompt = prompt::build_system_prompt(&ctx);

    // Build message history with current query appended
    let mut messages = history;
    messages.push(ChatMessage {
        role: "user".to_string(),
        content: query,
    });

    let llm = state
        .llm
        .lock()
        .map_err(|e| format!("LLM lock failed: {}", e))?
        .clone();

    let window_clone = window.clone();
    let _full_output = llm
        .generate_stream(&system_prompt, &messages, move |token| {
            if token.done {
                window_clone
                    .emit("forge-done", true)
                    .map_err(|e| crate::error::ForgeError::internal(e.to_string()))?;
            } else {
                window_clone
                    .emit("forge-token", &token.token)
                    .map_err(|e| crate::error::ForgeError::internal(e.to_string()))?;
            }
            Ok(())
        })
        .await
        .map_err(|e| e.to_string())?;

    Ok(())
}

// ─── Quick Tool Commands ─────────────────────────────────────────

#[tauri::command]
pub async fn forge_explain(
    state: tauri::State<'_, ForgeState>,
    window: tauri::Window,
) -> Result<(), String> {
    let ctx = state
        .context
        .lock()
        .map_err(|e| format!("State lock failed: {}", e))?
        .clone();

    let query = prompt::QuickPrompts::explain(&ctx);
    forge_stream_query(query, Vec::new(), Some(ctx), window, state).await
}

#[tauri::command]
pub async fn forge_ioc_lookup(
    iocs: Vec<String>,
    state: tauri::State<'_, ForgeState>,
    window: tauri::Window,
) -> Result<(), String> {
    let ctx = state
        .context
        .lock()
        .map_err(|e| format!("State lock failed: {}", e))?
        .clone();

    let query = prompt::QuickPrompts::ioc_lookup(&iocs);
    forge_stream_query(query, Vec::new(), Some(ctx), window, state).await
}

#[tauri::command]
pub async fn forge_attack_map(
    state: tauri::State<'_, ForgeState>,
    window: tauri::Window,
) -> Result<(), String> {
    let ctx = state
        .context
        .lock()
        .map_err(|e| format!("State lock failed: {}", e))?
        .clone();

    let query = prompt::QuickPrompts::attack_mapping(&ctx);
    forge_stream_query(query, Vec::new(), Some(ctx), window, state).await
}

#[tauri::command]
pub async fn forge_draft_paragraph(
    state: tauri::State<'_, ForgeState>,
    window: tauri::Window,
) -> Result<(), String> {
    let ctx = state
        .context
        .lock()
        .map_err(|e| format!("State lock failed: {}", e))?
        .clone();

    let query = prompt::QuickPrompts::draft_paragraph(&ctx);
    forge_stream_query(query, Vec::new(), Some(ctx), window, state).await
}

#[tauri::command]
pub async fn forge_synthesize_timeline(
    state: tauri::State<'_, ForgeState>,
    window: tauri::Window,
) -> Result<(), String> {
    let ctx = state
        .context
        .lock()
        .map_err(|e| format!("State lock failed: {}", e))?
        .clone();

    let query = prompt::QuickPrompts::synthesize_timeline(&ctx);
    forge_stream_query(query, Vec::new(), Some(ctx), window, state).await
}

// ─── Context Management ──────────────────────────────────────────

#[tauri::command]
pub fn forge_set_context(
    context: ForgeContext,
    state: tauri::State<'_, ForgeState>,
) -> Result<(), String> {
    let mut guard = state
        .context
        .lock()
        .map_err(|e| format!("State lock failed: {}", e))?;
    *guard = context;
    Ok(())
}

#[tauri::command]
pub fn forge_get_context(state: tauri::State<'_, ForgeState>) -> Result<ForgeContext, String> {
    let guard = state
        .context
        .lock()
        .map_err(|e| format!("State lock failed: {}", e))?;
    Ok(guard.clone())
}

#[tauri::command]
pub fn forge_clear_context(state: tauri::State<'_, ForgeState>) -> Result<(), String> {
    let mut guard = state
        .context
        .lock()
        .map_err(|e| format!("State lock failed: {}", e))?;
    *guard = ForgeContext::default();
    Ok(())
}

// ─── Health Check ────────────────────────────────────────────────

#[tauri::command]
pub async fn forge_health_check(state: tauri::State<'_, ForgeState>) -> Result<bool, String> {
    let llm = state
        .llm
        .lock()
        .map_err(|e| format!("LLM lock failed: {}", e))?
        .clone();
    Ok(llm.health_check().await)
}

/// List available models from the ollama server.
#[tauri::command]
pub async fn forge_list_models(state: tauri::State<'_, ForgeState>) -> Result<Vec<String>, String> {
    let llm = state
        .llm
        .lock()
        .map_err(|e| format!("LLM lock failed: {}", e))?
        .clone();
    llm.list_models().await.map_err(|e| e.to_string())
}

/// Update the LLM configuration at runtime.
#[tauri::command]
pub fn forge_set_llm_config(
    base_url: String,
    model: String,
    timeout_secs: u64,
    state: tauri::State<'_, ForgeState>,
) -> Result<(), String> {
    let mut guard = state
        .llm
        .lock()
        .map_err(|e| format!("LLM lock failed: {}", e))?;
    *guard = crate::llm::LlmClient::new(&base_url, &model, timeout_secs);
    Ok(())
}

// ─── IOC Enrichment ──────────────────────────────────────────────

#[tauri::command]
pub fn forge_enrich_ioc(
    ioc_value: String,
    state: tauri::State<'_, ForgeState>,
) -> Result<ioc::IocEnrichment, String> {
    Ok(ioc::enrich_ioc(&ioc_value, &state.kb))
}

#[tauri::command]
pub fn forge_classify_ioc(ioc_value: String) -> ioc::IocType {
    ioc::classify_ioc(&ioc_value)
}

#[tauri::command]
pub fn forge_kb_stats(state: tauri::State<'_, ForgeState>) -> (usize, usize, usize, usize, usize) {
    state.kb.stats()
}

// ─── Settings Commands ───────────────────────────────────────────

#[tauri::command]
pub fn forge_get_settings(state: tauri::State<'_, ForgeState>) -> Result<ForgeSettings, String> {
    let guard = state
        .settings
        .lock()
        .map_err(|e| format!("Settings lock failed: {}", e))?;
    Ok(guard.clone())
}

#[tauri::command]
pub fn forge_save_settings(
    new_settings: ForgeSettings,
    state: tauri::State<'_, ForgeState>,
) -> Result<(), String> {
    // Save to disk
    new_settings.save()?;

    // Update LLM client if config changed
    {
        let mut llm = state
            .llm
            .lock()
            .map_err(|e| format!("LLM lock failed: {}", e))?;
        *llm = crate::llm::LlmClient::new(
            &new_settings.llm_base_url,
            &new_settings.llm_model,
            new_settings.llm_timeout_secs,
        );
    }

    // Update stored settings
    let mut guard = state
        .settings
        .lock()
        .map_err(|e| format!("Settings lock failed: {}", e))?;
    *guard = new_settings;

    Ok(())
}

#[tauri::command]
pub fn forge_is_first_run() -> bool {
    ForgeSettings::is_first_run()
}

// ─── History Commands ────────────────────────────────────────────

#[tauri::command]
pub fn forge_list_conversations() -> Result<Vec<ConversationSummary>, String> {
    crate::history::list_conversations()
}

#[tauri::command]
pub fn forge_load_conversation(id: String) -> Result<Conversation, String> {
    Conversation::load(&id)
}

#[tauri::command]
pub fn forge_save_conversation(state: tauri::State<'_, ForgeState>) -> Result<(), String> {
    let guard = state
        .conversation
        .lock()
        .map_err(|e| format!("Conversation lock failed: {}", e))?;
    if let Some(ref conv) = *guard {
        conv.save()
    } else {
        Ok(())
    }
}

#[tauri::command]
pub fn forge_delete_conversation(id: String) -> Result<(), String> {
    Conversation::delete(&id)
}

#[tauri::command]
pub fn forge_new_conversation(
    case_name: Option<String>,
    state: tauri::State<'_, ForgeState>,
) -> Result<Conversation, String> {
    let conv = Conversation::new(case_name);
    let mut guard = state
        .conversation
        .lock()
        .map_err(|e| format!("Conversation lock failed: {}", e))?;
    *guard = Some(conv.clone());
    Ok(conv)
}

// ─── Export Commands ─────────────────────────────────────────────

#[tauri::command]
pub fn forge_export_text(id: String) -> Result<String, String> {
    let conv = Conversation::load(&id)?;
    Ok(crate::export::export_text(&conv))
}

#[tauri::command]
pub fn forge_export_markdown(id: String) -> Result<String, String> {
    let conv = Conversation::load(&id)?;
    Ok(crate::export::export_markdown(&conv))
}

#[tauri::command]
pub fn forge_export_html(id: String) -> Result<String, String> {
    let conv = Conversation::load(&id)?;
    Ok(crate::export::export_html(&conv))
}
