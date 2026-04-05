# strata-tree-sdk

Stable host/plugin interface for Strata Tree dynamic plugins.

## Exported Symbol
Every plugin must export:

```rust
#[no_mangle]
pub extern "C" fn strata_tree_plugin_entry() -> *mut dyn TreePlugin
```

## Required Trait
Implement `TreePlugin`:
- `describe() -> PluginInfo`
- `run(&mut self, &PluginContext) -> PluginResult`

## ABI Notes
- Strings crossing boundaries are C-compatible.
- Plugin must never free host memory.
- Host must treat plugin pointers as opaque.

## Safety
- Return deterministic errors (no panics).
- Keep processing read-only over evidence-derived data.
- Emit bounded output and clear messages.

## Build
`cargo build --release --lib`

The resulting shared library can be loaded from Tree's Plugins tab.
