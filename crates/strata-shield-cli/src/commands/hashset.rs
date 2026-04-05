// Extracted from main.rs - run_hashset_command

use crate::*;
use clap::Args;
use clap::Parser;
use clap::Subcommand;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "hashset", about = "Hash set management commands")]
pub struct HashsetArgs {
    #[command(subcommand)]
    pub cmd: HashsetSubcommand,
}

#[derive(Subcommand, Debug)]
pub enum HashsetSubcommand {
    List(HashsetCommonArgs),
    Stats(HashsetCommonArgs),
    Match(HashsetMatchArgs),
}

#[derive(Args, Debug, Clone)]
pub struct HashsetCommonArgs {
    #[arg(long = "case", short = 'c')]
    pub case: Option<String>,

    #[arg(long = "db", short = 'd')]
    pub db: Option<PathBuf>,

    #[arg(long = "json")]
    pub json: bool,

    #[arg(long = "json-result")]
    pub json_result: Option<PathBuf>,

    #[arg(long = "quiet", short = 'q')]
    pub quiet: bool,
}

#[derive(Args, Debug, Clone)]
pub struct HashsetMatchArgs {
    #[arg(long = "case", short = 'c')]
    pub case: Option<String>,

    #[arg(long = "db", short = 'd')]
    pub db: Option<PathBuf>,

    /// Path to NSRL CSV/SQLite (optional)
    #[arg(long = "nsrl")]
    pub nsrl: Option<PathBuf>,

    /// Path to known-good hashes (line- or csv-based, optional)
    #[arg(long = "known-good")]
    pub known_good: Option<PathBuf>,

    /// Path to known-bad hashes (line- or csv-based, optional)
    #[arg(long = "known-bad")]
    pub known_bad: Option<PathBuf>,

    /// Sample records returned in JSON output
    #[arg(long = "limit", short = 'l', default_value_t = 100)]
    pub limit: usize,

    #[arg(long = "json")]
    pub json: bool,

    #[arg(long = "json-result")]
    pub json_result: Option<PathBuf>,

    #[arg(long = "quiet", short = 'q')]
    pub quiet: bool,
}

pub fn execute(args: HashsetArgs, original_args: Vec<String>) {
    match args.cmd {
        HashsetSubcommand::List(common) => run_hashset_list(common, original_args),
        HashsetSubcommand::Stats(common) => run_hashset_stats(common, original_args),
        HashsetSubcommand::Match(match_args) => run_hashset_match(match_args, original_args),
    }
}
