pub mod aws_deep;
pub mod azure_deep;
pub mod google_workspace;
pub mod pcap_parser;

pub use aws_deep::AwsDeepParser;
pub use azure_deep::AzureDeepParser;
pub use google_workspace::GoogleWorkspaceParser;
pub use pcap_parser::PcapParser;
