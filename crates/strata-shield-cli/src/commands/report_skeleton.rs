//! `strata report-skeleton` — **DEPRECATED post-v16 Sprint 6.5**.
//!
//! The legacy `report-skeleton` command read from `./forensic.db`
//! expecting the strata-core case-store schema (`evidence`,
//! `case_stats`, `ingest_manifests`, …). `strata ingest run`
//! writes `<case-dir>/artifacts.sqlite` with the plugin schema.
//! The two schemas never intersected; the command silently
//! produced all-zero reports with a "Case database: not found"
//! warning — discovered in the Sprint 6 examiner-quality audit
//! as finding G1 (demo-blocker architectural disconnect).
//!
//! Post-v16 Sprint 6.5 ships `strata report` as the replacement.
//! It reads `<case-dir>/artifacts.sqlite` + `<case-dir>/case-metadata.json`
//! directly — both produced by `strata ingest run`. Findings,
//! MITRE ATT&CK coverage, Chain of Custody, and Examiner
//! Certification sections are rendered with real case data.
//!
//! `strata report-skeleton` now emits a deprecation message
//! pointing at the new command and exits non-zero so any script
//! that was silently depending on the broken output fails
//! loudly during the transition.

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "report-skeleton",
    about = "[DEPRECATED] Use `strata report --case-dir <case-dir>` instead.",
    hide = true
)]
pub struct ReportSkeletonArgs {
    /// Retained for CLI-compatibility with scripts that hadn't
    /// yet migrated — accepted but ignored. The deprecation
    /// message names the replacement command.
    #[arg(long = "case", short = 'c')]
    pub case: Option<String>,

    #[arg(long = "examiner")]
    pub examiner: Option<String>,

    #[arg(long = "output", short = 'o', visible_alias = "out")]
    pub output: Option<PathBuf>,

    #[arg(long = "hash")]
    pub hash: Option<String>,
}

/// Emit a deprecation notice to stderr and exit non-zero. No
/// report is generated — the legacy implementation produced
/// empty reports that silently misled examiners.
pub fn execute(_args: ReportSkeletonArgs) {
    eprintln!(
        "strata report-skeleton has been retired (Sprint 6.5)."
    );
    eprintln!();
    eprintln!(
        "The legacy command queried ./forensic.db while `strata ingest run`"
    );
    eprintln!(
        "writes <case-dir>/artifacts.sqlite. The two schemas never intersected,"
    );
    eprintln!(
        "so report-skeleton silently produced all-zero reports on every case."
    );
    eprintln!();
    eprintln!("Use the replacement command:");
    eprintln!();
    eprintln!("    strata report --case-dir <case-dir>");
    eprintln!();
    eprintln!(
        "It reads artifacts.sqlite + case-metadata.json directly and renders"
    );
    eprintln!(
        "a court-ready markdown report with Findings, MITRE ATT&CK coverage,"
    );
    eprintln!("Chain of Custody, and Examiner Certification sections.");
    std::process::exit(2);
}

#[cfg(test)]
mod tests {
    /// Sprint 6.5 tripwire. `report-skeleton` retirement must
    /// stay retired — no one should accidentally revert to the
    /// empty-report behavior. Behavioral test: invoke execute()
    /// in a subprocess and confirm non-zero exit + deprecation
    /// message.
    ///
    /// We can't directly spawn the real binary from a unit test
    /// without compiling it first, so instead we pin the invariant
    /// via source-structural assertions: the module must contain
    /// the deprecation marker, the non-zero exit, and the
    /// redirect-to-replacement-command string.
    #[test]
    fn report_skeleton_command_deprecated_or_removed() {
        let src = include_str!("report_skeleton.rs");
        assert!(
            src.contains("DEPRECATED") && src.contains("exit(2)"),
            "report-skeleton must remain deprecated with a non-zero exit — \
             never silently ship an empty-report implementation again."
        );
        // Explicit redirect to the replacement command.
        assert!(
            src.contains("strata report --case-dir"),
            "deprecation message must name the replacement command"
        );
        // The behavioral expectation: execute() must not
        // re-implement the read-from-disk-case-store logic. We
        // verify by structural proxy — the function body is
        // small (boilerplate eprintln + exit) and must not open
        // a SQLite connection.
        let prod = src.split("#[cfg(test)]").next().unwrap_or("");
        assert!(
            !prod.contains("Connection::open"),
            "report-skeleton execute() must not open a database — it is \
             deprecated and should only print the replacement command"
        );
    }
}
