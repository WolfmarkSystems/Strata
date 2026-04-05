# Initial Stub Completion Super Prompt

## Prompt

You are implementing one unfinished module in `d:\forensic-suite`. Start by inspecting the current code and confirming the exact stub boundary before writing code.

Target: complete the VHD virtualization bridge in:
- `engine/src/virtualization/vhd.rs`

Required behavior:
- Bridge `VhdContainer` into the `VirtualFileSystem` abstraction
- Expose at least one synthetic root volume node when direct filesystem parsing is unavailable
- Support safe `read_volume_at()` calls through the underlying container
- Return deterministic `ForensicError` values for unsupported navigation paths
- Preserve the no-touch evidence policy

Required output:
- Full Rust code, not pseudocode
- Unit tests covering:
  - root metadata
  - volume exposure
  - unsupported file open path
  - safe read bounds behavior
- `cargo test` command
- brief explanation of limitations still remaining

Constraints:
- No `unsafe`
- No TODO placeholders
- No panics on malformed input
- Use existing engine types and error enums
- Prefer small helper functions with explicit error propagation

## Example Generated Snippet

```rust
fn synthetic_volume_entry(&self) -> VfsEntry {
    VfsEntry {
        path: PathBuf::from("/vol0"),
        name: "vol0".to_string(),
        is_dir: true,
        size: self.total_size(),
        modified: None,
    }
}

fn clamp_read_size(requested: usize, available: u64, offset: u64) -> usize {
    let remaining = available.saturating_sub(offset);
    requested.min(remaining as usize)
}
```

## Why This Prompt Works

It narrows the scope to one real stub, demands complete code plus tests, and prevents the model from drifting into architecture-only output. It also keeps the implementation aligned with the repository’s existing error and VFS contracts.

