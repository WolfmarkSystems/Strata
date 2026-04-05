// Extracted from main.rs - run_ioc_add_command

use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(name = "ioc-add", about = "Add IOC rule records")]
pub struct IocAddArgs {
    #[arg(long, short = 'n', help = "IOC rule name")]
    pub name: String,

    #[arg(
        long = "type",
        short = 't',
        default_value = "KEYWORD",
        help = "IOC rule type"
    )]
    pub rule_type: String,

    #[arg(long, short = 's', default_value = "MEDIUM", help = "IOC severity")]
    pub severity: String,

    #[arg(long, short = 'p', help = "Rule pattern")]
    pub pattern: String,

    #[arg(long = "hash-type", help = "Hash algorithm type")]
    pub hash_type: Option<String>,

    #[arg(long = "tag", help = "Rule tag (repeatable)")]
    pub tags: Vec<String>,
}

pub fn execute(args: IocAddArgs) {
    println!(
        "Adding IOC rule: {} (type={}, severity={})",
        args.name, args.rule_type, args.severity
    );
    println!("Pattern: {}", args.pattern);
    if let Some(hash_type) = &args.hash_type {
        println!("Hash type: {}", hash_type);
    }
    if !args.tags.is_empty() {
        println!("Tags: {:?}", args.tags);
    }

    println!("\nNote: Rule will be added when database support is enabled.");
}
