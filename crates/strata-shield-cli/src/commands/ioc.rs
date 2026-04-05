// Extracted from main.rs - run_ioc_command

use clap::Parser;
use clap::Subcommand;

#[derive(Parser, Debug, Clone)]
#[command(name = "ioc", about = "IOC rule operations")]
pub struct IocArgs {
    #[command(subcommand)]
    pub command: Option<IocCommand>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum IocCommand {
    Add(crate::commands::ioc_add::IocAddArgs),
    List(crate::commands::ioc_list::IocListArgs),
    Scan(crate::commands::ioc_scan::IocScanArgs),
}

pub fn execute(args: IocArgs) {
    match args.command {
        Some(IocCommand::Add(cmd)) => crate::commands::ioc_add::execute(cmd),
        Some(IocCommand::List(cmd)) => crate::commands::ioc_list::execute(cmd),
        Some(IocCommand::Scan(cmd)) => crate::commands::ioc_scan::execute(cmd),
        None => {
            eprintln!("Usage: forensic-cli ioc <subcommand>");
            eprintln!();
            eprintln!("Subcommands:");
            eprintln!("  add     Add a new IOC rule");
            eprintln!("  list    List IOC rules");
            eprintln!("  scan    Run IOC scan");
            std::process::exit(1);
        }
    }
}
