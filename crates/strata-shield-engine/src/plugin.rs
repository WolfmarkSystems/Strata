use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use arc_swap::ArcSwap;
use libloading::{Library, Symbol};
use notify::{Watcher, RecursiveMode, Config, Event};
use strata_plugin_sdk::{StrataPlugin, PluginContext, PluginResult};
use tracing::{info, error, warn};
use tokio::sync::mpsc;

pub type PluginMap = HashMap<String, Arc<LoadedPlugin>>;

pub struct LoadedPlugin {
    pub name: String,
    pub path: PathBuf,
    pub plugin: Box<dyn StrataPlugin>,
    _library: Library, // Must be kept alive for the plugin to work
}

pub struct PluginManager {
    active_plugins: Arc<ArcSwap<PluginMap>>,
    plugin_dir: PathBuf,
}

impl PluginManager {
    pub fn new(plugin_dir: &Path) -> Self {
        Self {
            active_plugins: Arc::new(ArcSwap::from_pointee(HashMap::new())),
            plugin_dir: plugin_dir.to_path_buf(),
        }
    }

    pub fn start_hot_reload(&self) -> anyhow::Result<()> {
        let (tx, mut rx) = mpsc::channel(32);
        let plugin_dir = self.plugin_dir.clone();
        let active_plugins = self.active_plugins.clone();

        // Initial scan
        self.reload_all()?;

        // Start watching the plugin directory
        tokio::spawn(async move {
            let mut watcher = notify::recommended_watcher(move |res: notify::Result<Event>| {
                if let Ok(event) = res {
                    if event.kind.is_modify() || event.kind.is_create() {
                        let _ = tx.blocking_send(());
                    }
                }
            }).expect("Failed to start watcher");

            watcher.watch(&plugin_dir, RecursiveMode::NonRecursive).expect("Failed to watch dir");

            while let Some(_) = rx.recv().await {
                info!("Plugin change detected, reloading...");
                // Note: In a real app, we might want to debounce this
                if let Err(e) = Self::reload_all_internal(&plugin_dir, &active_plugins) {
                    error!("Hot-reload failed: {}", e);
                }
            }
        });

        Ok(())
    }

    pub fn reload_all(&self) -> anyhow::Result<()> {
        Self::reload_all_internal(&self.plugin_dir, &self.active_plugins)
    }

    fn reload_all_internal(plugin_dir: &Path, active_plugins: &ArcSwap<PluginMap>) -> anyhow::Result<()> {
        let mut new_plugins = HashMap::new();

        if !plugin_dir.exists() {
            std::fs::create_dir_all(plugin_dir)?;
        }

        let entries = std::fs::read_dir(plugin_dir)?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some(if cfg!(windows) { "dll" } else { "so" }) {
                match Self::load_plugin(&path) {
                    Ok(lp) => {
                        info!("Loaded plugin: {} from {:?}\"", lp.name, path);
                        new_plugins.insert(lp.name.clone(), Arc::new(lp));
                    }
                    Err(e) => error!("Failed to load plugin {:?}: {}", path, e),
                }
            }
        }

        active_plugins.store(Arc::new(new_plugins));
        Ok(())
    }

    fn load_plugin(path: &Path) -> anyhow::Result<LoadedPlugin> {
        // IMPORTANT: To allow overwriting the DLL/SO while loaded, 
        // we copy it to a temp file first.
        let temp_dir = std::env::temp_dir().join("strata_plugins");
        std::fs::create_dir_all(&temp_dir)?;
        
        let file_name = path.file_name().unwrap();
        let temp_path = temp_dir.join(file_name);
        std::fs::copy(path, &temp_path)?;

        unsafe {
            let lib = Library::new(&temp_path)?;
            let constructor: Symbol<extern "C" fn() -> *mut std::ffi::c_void> =
                lib.get(b"create_plugin")?;
            let plugin_ptr = constructor();
            if plugin_ptr.is_null() {
                return Err(anyhow::anyhow!("Plugin constructor returned null pointer"));
            }
            let plugin = *Box::from_raw(plugin_ptr as *mut Box<dyn StrataPlugin>);
            
            Ok(LoadedPlugin {
                name: plugin.name().to_string(),
                path: path.to_path_buf(),
                plugin,
                _library: lib,
            })
        }
    }

    pub fn run_all(&self, context: PluginContext) -> Vec<PluginResult> {
        let plugins = self.active_plugins.load();
        plugins.values().map(|lp| lp.plugin.run(context.clone())).collect()
    }

    pub fn get_active_plugin_names(&self) -> Vec<String> {
        self.active_plugins.load().keys().cloned().collect()
    }
}
