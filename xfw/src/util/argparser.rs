use clap::{Args, Parser, Subcommand};

/// A fast IP blocker.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None, author="Kakeeto Pius")]
pub struct Xfw {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Start the xfw IP blocker.
    Start(StartArgs),
    /// Block an IP or IP range.
    Block,
    /// Unblock an IP or IP range.
    Unblock,
    /// List blocked IPs and IP ranges.
    List,
}

#[derive(Args, Debug)]
pub struct StartArgs {
    /// The network interface(s) to block ips from.
    #[arg(long, short, required = true, num_args=1..)]
    pub ifaces: Vec<String>,
}
