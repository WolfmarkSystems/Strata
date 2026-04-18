# Strata Plugin Architecture

Strata plugins implement the `StrataPlugin` trait from
`crates/strata-plugin-sdk`. Each plugin owns a clearly scoped slice of
the forensic artifact space (see the plugin → source mapping in
`CLAUDE.md`).

Strata supports two plugin delivery models. Today, only the static
model is wired into release builds.

## Static plugins (the production path)

All 22 in-tree plugins are statically linked into
`strata-engine-adapter` at compile time. Registration happens in a
single function:

```
crates/strata-engine-adapter/src/plugins.rs :: build_plugins()
```

The Tauri desktop app, the CLI headless runner
(`strata ingest run`, added in FIX-1), and the legacy egui viewer all
resolve plugins through this one registry. No dynamic loading, no
runtime plugin discovery. This is the CJIS-compliance path — the
shipped binary is an immutable artifact whose plugin set cannot be
swapped at runtime.

### Adding a new static plugin

1. Create the crate under `plugins/strata-plugin-<name>/`.
2. Add it to the `members = [...]` list in the workspace `Cargo.toml`.
3. Implement `StrataPlugin` from `strata-plugin-sdk`. Follow the
   plugin → source mapping in `CLAUDE.md` — do not mix OS-specific
   logic across plugins.
4. Add a path dep in `crates/strata-engine-adapter/Cargo.toml`:
   ```
   strata-plugin-<name> = { path = "../../plugins/strata-plugin-<name>" }
   ```
5. Add a `Box::new(strata_plugin_<name>::<Name>Plugin::new())` line
   in `build_plugins()`, **before** `SigmaPlugin::new()` (Sigma must
   remain last so its correlation pass sees every other plugin's
   artifacts through `prior_results`).
6. Run the registration check (FIX-6):
   `cargo run -p strata-verify-plugins` — it fails the build if any
   workspace plugin is missing from the registry.

## Dynamic plugins (scaffolding only)

`plugins/strata-plugin-index` is declared as `crate-type =
["cdylib"]`. It exists as the seed for a future runtime-loaded plugin
surface — the ABI / signing / audit story around dynamic loading is
not finished, so the crate is intentionally **not** wired into
`strata-engine-adapter`.

What this means today:

- The cdylib produced by `strata-plugin-index` is built by the
  workspace but loaded by no running Strata binary.
- FIX-6's plugin registration check treats `strata-plugin-index` and
  `strata-plugin-tree-example` as opt-out — neither is expected to
  appear in `build_plugins()`.
- The crate is OK to keep shipping for now — it documents the shape
  of a future dynamic plugin. When we commit to dynamic loading,
  either:
  - **Option A:** promote it to dual-crate (`crate-type = ["rlib",
    "cdylib"]`) and add it to the static registry too, or
  - **Option B:** implement a vetted loader (signature verification,
    audit trail, sandboxed exec) and document it here.

Until one of those happens, the cdylib is scaffolding. Don't wire
loose plugin-loading code into the engine path.

## Sigma is always last

`SigmaPlugin` is Strata's correlation engine — it reads
`prior_results` (the previous plugins' output) and emits
cross-artifact findings (34 MITRE ATT&CK kill-chain rules). It must
stay at the tail of `build_plugins()` and no other plugin should
carry correlation logic. Cross-artifact rules belong in Sigma.

## Static registry at a glance

Current static roster (22 plugins, Sigma last):

```
remnant → chronicle → cipher → trace → specter → conduit → nimbus
→ wraith → vector → recon → phantom → guardian → netflow → mactrace
→ sentinel → csam → apex → carbon → pulse → vault → arbor → sigma
```

The CLI's `strata ingest run` executes plugins in this same order
and threads `prior_results` forward, so every plugin sees everything
that ran before it — and Sigma sees the full set.
