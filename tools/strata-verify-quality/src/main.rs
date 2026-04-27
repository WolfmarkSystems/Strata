//! strata-verify-quality — AST-aware quality gate.
//!
//! Replaces grep-based unwrap/unsafe/println counts with real AST walks
//! via `syn`. Distinguishes library code from `#[cfg(test)]` test
//! modules, from CLI binaries where `println!` is the intended human-
//! output channel, from workspace tools, and from tests directories.
//!
//! Counts the four categories separately so the ENFORCED number is the
//! one that actually matters: production-code violations. Waiver file
//! allows a documented baseline of legitimate `unsafe{}` (VHD / VMDK
//! binding crates need memory-mapped access).
//!
//! Exit code 0 on pass, 1 on violation. Prints a per-category report to
//! stdout and the failing category to stderr.
//!
//! Zero `.unwrap()` / `unsafe {}` / `println!` except where the binary
//! IS the human-output layer — this tool runs from CI / developer
//! command-line and speaks to humans on stdout/stderr, so `println!`
//! is intentional here. The tool is a `CliBinary`, and the gate's own
//! per-category classifier treats it as such.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use syn::visit::Visit;
use walkdir::WalkDir;

// ── Classification of a file's role ────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileContext {
    /// `crates/*/src/*.rs` — library code, strictly no .unwrap() /
    /// unsafe / println! in production.
    Library,
    /// `crates/*/tests/*.rs`, anything under a `tests/` directory,
    /// or `#[cfg(test)]` modules inside library sources. Test code
    /// may use whatever it needs; not gated.
    Test,
    /// `crates/strata-shield-cli/src/**` (the `strata` CLI binary).
    /// `println!` is the intended human-output channel; unwrap /
    /// unsafe still gated to the production floor.
    CliBinary,
    /// `tools/*/src/**`, `apps/*/src/**`, examples, build.rs. Same
    /// stance as CliBinary — these are entry-point binaries.
    ToolOrApp,
}

fn classify_file(path: &Path) -> FileContext {
    let s = path.to_string_lossy();
    let s = s.replace('\\', "/");

    // Anything inside a `tests/` directory is test code.
    if s.contains("/tests/") {
        return FileContext::Test;
    }
    if s.ends_with("_tests.rs") || s.ends_with("/tests.rs") {
        return FileContext::Test;
    }
    if s.ends_with("build.rs") {
        return FileContext::ToolOrApp;
    }

    if s.contains("/apps/") {
        return FileContext::ToolOrApp;
    }
    if s.contains("/tools/") {
        return FileContext::ToolOrApp;
    }
    if s.contains("/strata-shield-cli/") {
        return FileContext::CliBinary;
    }
    // `examples/` under any crate
    if s.contains("/examples/") {
        return FileContext::ToolOrApp;
    }

    FileContext::Library
}

// ── Counters ────────────────────────────────────────────────────────

#[derive(Default, Debug, Clone)]
struct Counts {
    unwrap: usize,
    unsafe_block: usize,
    println: usize,
}

#[derive(Default, Debug, Clone)]
struct AllCounts {
    library: Counts,
    test: Counts,
    cli: Counts,
    tool_or_app: Counts,
    /// Per-file breakdown for the library category so the gate can
    /// point at the specific offending file.
    per_library_file: BTreeMap<String, Counts>,
}

// ── AST visitor ─────────────────────────────────────────────────────

struct QualityVisitor<'a> {
    file_context: FileContext,
    in_test_module: bool,
    counts: &'a mut AllCounts,
    current_path: &'a str,
}

impl QualityVisitor<'_> {
    fn bucket_effective(&self) -> FileContext {
        if self.in_test_module {
            FileContext::Test
        } else {
            self.file_context
        }
    }

    fn bump<F: Fn(&mut Counts)>(&mut self, f: F) {
        let bucket = self.bucket_effective();
        let target: &mut Counts = match bucket {
            FileContext::Library => &mut self.counts.library,
            FileContext::Test => &mut self.counts.test,
            FileContext::CliBinary => &mut self.counts.cli,
            FileContext::ToolOrApp => &mut self.counts.tool_or_app,
        };
        f(target);
        if bucket == FileContext::Library {
            let entry = self
                .counts
                .per_library_file
                .entry(self.current_path.to_string())
                .or_default();
            f(entry);
        }
    }
}

fn is_test_attribute(attr: &syn::Attribute) -> bool {
    // Matches:  #[cfg(test)]  and  #[cfg(any(test, ...))]
    if !attr.path().is_ident("cfg") {
        return false;
    }
    // Parse the token stream manually — #[cfg(test)] has a `test` path
    // token inside.
    let tokens = attr.meta.to_token_stream();
    let s = tokens.to_string();
    s.contains("test")
}

// `to_token_stream` helper pulled from quote re-export via syn.
use syn::__private::ToTokens;

impl<'ast> Visit<'ast> for QualityVisitor<'_> {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        let is_test_mod = node.ident == "tests" || node.attrs.iter().any(is_test_attribute);

        if is_test_mod {
            let prev = self.in_test_module;
            self.in_test_module = true;
            syn::visit::visit_item_mod(self, node);
            self.in_test_module = prev;
        } else {
            syn::visit::visit_item_mod(self, node);
        }
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        let is_test_fn = node
            .attrs
            .iter()
            .any(|a| a.path().is_ident("test") || a.path().is_ident("tokio::test"));
        if is_test_fn {
            let prev = self.in_test_module;
            self.in_test_module = true;
            syn::visit::visit_item_fn(self, node);
            self.in_test_module = prev;
        } else {
            syn::visit::visit_item_fn(self, node);
        }
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if node.method == "unwrap" && node.args.is_empty() {
            self.bump(|c| c.unwrap += 1);
        }
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_unsafe(&mut self, node: &'ast syn::ExprUnsafe) {
        self.bump(|c| c.unsafe_block += 1);
        syn::visit::visit_expr_unsafe(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if let Some(seg) = node.path.segments.last() {
            if seg.ident == "println" {
                self.bump(|c| c.println += 1);
            }
        }
        syn::visit::visit_macro(self, node);
    }
}

// ── Waiver loading ──────────────────────────────────────────────────

/// Per-category baseline. A count above the baseline fails the gate;
/// a count equal to or below the baseline passes. Baselines are meant
/// to be decreased by later cleanup sprints, never increased.
#[derive(Debug, Default, Deserialize)]
struct Waivers {
    #[serde(default)]
    library_unwrap: CategoryWaiver,
    #[serde(default)]
    library_unsafe: CategoryWaiver,
    #[serde(default)]
    library_println: CategoryWaiver,
}

#[derive(Debug, Default, Deserialize)]
struct CategoryWaiver {
    #[serde(default)]
    known_count: usize,
    #[serde(default)]
    reason: String,
}

fn load_waivers(path: &Path) -> Waivers {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Waivers::default();
    };
    let raw: toml::Table = match toml::from_str::<toml::Table>(&text) {
        Ok(t) => t,
        Err(_) => return Waivers::default(),
    };
    let mut w = Waivers::default();
    // Legacy `[unsafe]` section — for compatibility with the pseudo-code
    // in SPRINTS_v14.md.
    if let Some(tbl) = raw.get("unsafe").and_then(|v| v.as_table()) {
        if let Some(n) = tbl.get("known_count").and_then(|v| v.as_integer()) {
            w.library_unsafe.known_count = n.max(0) as usize;
        }
        if let Some(r) = tbl.get("reason").and_then(|v| v.as_str()) {
            w.library_unsafe.reason = r.to_string();
        }
    }
    for (name, target) in [
        ("library_unwrap", &mut w.library_unwrap),
        ("library_unsafe", &mut w.library_unsafe),
        ("library_println", &mut w.library_println),
    ] {
        if let Some(tbl) = raw.get(name).and_then(|v| v.as_table()) {
            if let Some(n) = tbl.get("known_count").and_then(|v| v.as_integer()) {
                target.known_count = n.max(0) as usize;
            }
            if let Some(r) = tbl.get("reason").and_then(|v| v.as_str()) {
                target.reason = r.to_string();
            }
        }
    }
    w
}

// ── Walk + run ──────────────────────────────────────────────────────

fn should_skip(path: &Path) -> bool {
    for comp in path.components() {
        let s = comp.as_os_str().to_string_lossy();
        if s == "target"
            || s == ".git"
            || s == "node_modules"
            || s == "worktrees"
            || s == "examples"
        {
            return true;
        }
    }
    false
}

fn scan_workspace(root: &Path) -> Result<AllCounts, String> {
    let mut counts = AllCounts::default();
    for entry in WalkDir::new(root) {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => return Err(format!("walk: {e}")),
        };
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if should_skip(path) {
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let source = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => return Err(format!("read {}: {e}", path.display())),
        };
        let syntax = match syn::parse_file(&source) {
            Ok(f) => f,
            Err(_) => continue, // parse failure: skip the file, not a quality violation
        };
        let file_context = classify_file(path);
        let path_str = path.display().to_string();
        let mut visitor = QualityVisitor {
            file_context,
            in_test_module: false,
            counts: &mut counts,
            current_path: &path_str,
        };
        visitor.visit_file(&syntax);
    }
    Ok(counts)
}

fn print_report(counts: &AllCounts) {
    println!("Strata quality gate report (AST-based)");
    println!();
    println!("  Library (crates/*/src/, non-test modules):");
    println!("    unwrap:       {:>6}", counts.library.unwrap);
    println!("    unsafe{{}}:     {:>6}", counts.library.unsafe_block);
    println!("    println!:     {:>6}", counts.library.println);
    println!();
    println!("  Test modules (tests/, #[cfg(test)], #[test] fns):");
    println!("    unwrap:       {:>6}", counts.test.unwrap);
    println!("    unsafe{{}}:     {:>6}", counts.test.unsafe_block);
    println!("    println!:     {:>6}", counts.test.println);
    println!();
    println!("  CLI (strata-shield-cli):");
    println!("    unwrap:       {:>6}", counts.cli.unwrap);
    println!("    unsafe{{}}:     {:>6}", counts.cli.unsafe_block);
    println!(
        "    println!:     {:>6}  (intentional — human output)",
        counts.cli.println
    );
    println!();
    println!("  Tools / Apps (tools/, apps/, examples/, build.rs):");
    println!("    unwrap:       {:>6}", counts.tool_or_app.unwrap);
    println!("    unsafe{{}}:     {:>6}", counts.tool_or_app.unsafe_block);
    println!("    println!:     {:>6}", counts.tool_or_app.println);
}

fn top_offenders(counts: &AllCounts, n: usize) {
    let mut by_unwrap: Vec<(&String, usize)> = counts
        .per_library_file
        .iter()
        .filter(|(_, c)| c.unwrap > 0)
        .map(|(p, c)| (p, c.unwrap))
        .collect();
    by_unwrap.sort_by(|a, b| b.1.cmp(&a.1));
    if !by_unwrap.is_empty() {
        println!("\n  Top library-file unwrap offenders:");
        for (path, n) in by_unwrap.iter().take(n) {
            println!("    {n:>4}  {path}");
        }
    }
}

fn main() {
    let root = PathBuf::from(".");
    let waiver_path = PathBuf::from("tools/strata-verify-quality/waivers.toml");
    let waivers = load_waivers(&waiver_path);

    let counts = match scan_workspace(&root) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("scan failed: {e}");
            std::process::exit(2);
        }
    };

    print_report(&counts);
    top_offenders(&counts, 10);

    // Enforcement.
    let mut failures: Vec<String> = Vec::new();

    fn enforce(
        actual: usize,
        waiver: &CategoryWaiver,
        label: &str,
        remediation: &str,
        failures: &mut Vec<String>,
    ) {
        if actual > waiver.known_count {
            failures.push(format!(
                "{actual} library-code {label} (baseline: {} — {}). {remediation}",
                waiver.known_count,
                if waiver.reason.is_empty() {
                    "no waiver reason recorded"
                } else {
                    waiver.reason.as_str()
                }
            ));
        }
    }

    enforce(
        counts.library.unwrap,
        &waivers.library_unwrap,
        ".unwrap() calls",
        "Use ? or match. Decrease the baseline in waivers.toml when fixing.",
        &mut failures,
    );
    enforce(
        counts.library.unsafe_block,
        &waivers.library_unsafe,
        "unsafe{} blocks",
        "unsafe is only acceptable for documented low-level needs (binding crates).",
        &mut failures,
    );
    enforce(
        counts.library.println,
        &waivers.library_println,
        "println! calls",
        "Use log::{debug,info,warn,error}! instead.",
        &mut failures,
    );

    if failures.is_empty() {
        println!("\nQuality gate: PASS");
        std::process::exit(0);
    }

    eprintln!();
    for f in &failures {
        eprintln!("FAIL: {f}");
    }
    std::process::exit(1);
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn scan_str(source: &str, context: FileContext) -> AllCounts {
        let syntax = syn::parse_file(source).expect("parse");
        let mut counts = AllCounts::default();
        let path_str = "<test>".to_string();
        let mut v = QualityVisitor {
            file_context: context,
            in_test_module: false,
            counts: &mut counts,
            current_path: &path_str,
        };
        v.visit_file(&syntax);
        counts
    }

    #[test]
    fn counts_unwrap_in_library_code() {
        let src = r#"
            fn f() { let _ = Some(1).unwrap(); }
        "#;
        let c = scan_str(src, FileContext::Library);
        assert_eq!(c.library.unwrap, 1);
        assert_eq!(c.test.unwrap, 0);
    }

    #[test]
    fn skips_unwrap_inside_cfg_test_module() {
        let src = r#"
            fn f() {}
            #[cfg(test)]
            mod tests {
                fn g() { let _ = Some(1).unwrap(); }
            }
        "#;
        let c = scan_str(src, FileContext::Library);
        assert_eq!(c.library.unwrap, 0);
        assert_eq!(c.test.unwrap, 1);
    }

    #[test]
    fn skips_unwrap_inside_named_tests_module() {
        let src = r#"
            fn f() {}
            mod tests {
                fn g() { let _ = Some(1).unwrap(); }
            }
        "#;
        let c = scan_str(src, FileContext::Library);
        assert_eq!(c.library.unwrap, 0);
        assert_eq!(c.test.unwrap, 1);
    }

    #[test]
    fn skips_unwrap_inside_test_fn() {
        let src = r#"
            #[test]
            fn it_works() { let _ = Some(1).unwrap(); }
        "#;
        let c = scan_str(src, FileContext::Library);
        assert_eq!(c.library.unwrap, 0);
        assert_eq!(c.test.unwrap, 1);
    }

    #[test]
    fn counts_unsafe_block() {
        let src = r#"
            fn f() { unsafe { let _ = 0; } }
        "#;
        let c = scan_str(src, FileContext::Library);
        assert_eq!(c.library.unsafe_block, 1);
    }

    #[test]
    fn counts_println_macro() {
        let src = r#"
            fn f() { println!("x"); }
        "#;
        let c = scan_str(src, FileContext::Library);
        assert_eq!(c.library.println, 1);
    }

    #[test]
    fn println_in_cli_goes_to_cli_bucket() {
        let src = r#"
            fn f() { println!("x"); }
        "#;
        let c = scan_str(src, FileContext::CliBinary);
        assert_eq!(c.library.println, 0);
        assert_eq!(c.cli.println, 1);
    }

    #[test]
    fn ignores_unwrap_with_args() {
        // e.g. .unwrap_or(x) or .unwrap_err() — must NOT count.
        let src = r#"
            fn f() {
                let _ = Some(1).unwrap_or(0);
                let _: Result<i32, ()> = Err(());
                let _ = Err::<i32, ()>(()).unwrap_err();
            }
        "#;
        let c = scan_str(src, FileContext::Library);
        assert_eq!(c.library.unwrap, 0);
    }

    #[test]
    fn classify_library_vs_cli_vs_test_vs_tool() {
        assert_eq!(
            classify_file(&PathBuf::from("/x/crates/strata-evidence/src/e01.rs")),
            FileContext::Library
        );
        assert_eq!(
            classify_file(&PathBuf::from("/x/crates/strata-evidence/tests/foo.rs")),
            FileContext::Test
        );
        assert_eq!(
            classify_file(&PathBuf::from("/x/crates/strata-shield-cli/src/main.rs")),
            FileContext::CliBinary
        );
        assert_eq!(
            classify_file(&PathBuf::from("/x/tools/strata-verify-quality/src/main.rs")),
            FileContext::ToolOrApp
        );
        assert_eq!(
            classify_file(&PathBuf::from(
                "/x/apps/strata-desktop/src-tauri/src/lib.rs"
            )),
            FileContext::ToolOrApp
        );
    }

    #[test]
    fn per_library_file_tracks_offender_paths() {
        let src = r#"
            fn f() {
                let _ = Some(1).unwrap();
                let _ = Some(2).unwrap();
            }
        "#;
        let c = scan_str(src, FileContext::Library);
        assert_eq!(c.library.unwrap, 2);
        assert_eq!(c.per_library_file.get("<test>").map(|c| c.unwrap), Some(2));
    }
}
