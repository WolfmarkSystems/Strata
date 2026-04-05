use strata_tree_sdk::{PluginContext, PluginInfo, PluginResult, PluginStr, TreePlugin};

struct ExamplePlugin;

impl TreePlugin for ExamplePlugin {
    fn describe(&self) -> PluginInfo {
        PluginInfo {
            name: PluginStr::from_static("Tree Example Plugin"),
            description: PluginStr::from_static("Reference implementation for Strata plugin SDK"),
            version: PluginStr::from_static("0.1.0"),
            author: PluginStr::from_static("Wolfmark Systems"),
            category: PluginStr::from_static("Utility"),
        }
    }

    fn run(&mut self, _ctx: &PluginContext) -> PluginResult {
        PluginResult::ok("Example plugin executed")
    }
}

#[no_mangle]
#[allow(improper_ctypes_definitions)]
pub extern "C" fn strata_tree_plugin_entry() -> *mut dyn TreePlugin {
    Box::into_raw(Box::new(ExamplePlugin))
}

#[no_mangle]
pub extern "C" fn create_plugin_tree_example() -> *mut std::ffi::c_void {
    Box::into_raw(Box::new(1u8)) as *mut std::ffi::c_void
}
