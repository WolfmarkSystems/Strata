// Extracted from main.rs - run_ioc_list_command

use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(name = "ioc-list", about = "List IOC rules")]
pub struct IocListArgs {}

pub fn execute(_args: IocListArgs) {
    println!("=== IOC Rules ===");
    println!();
    println!("Note: Database listing not yet implemented in this demo.");
    println!("Rules would be listed from the database.");
}
