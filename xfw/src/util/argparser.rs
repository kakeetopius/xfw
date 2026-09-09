use clap::{Args, Parser, Subcommand};

/// A fast IP blocker.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None, author="Kakeeto Pius")]
pub struct Xfw {
    #[command(subcommand)]
    pub command: Commands,

    /// Directory where to pin the maps containing the blocked IPs or where the maps are pinned.
    #[arg(long, short, default_value = "/sys/fs/bpf", global = true)]
    pub maps_dir: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Start the xfw IP blocker.
    Start(StartArgs),
    /// Block an IP or IP range.
    Block(BlockArgs),
    /// Unblock an IP or IP range.
    Unblock(UnBlockArgs),
    /// List blocked IPs and IP ranges.
    List(ListArgs),
}

#[derive(Args, Debug)]
pub struct StartArgs {
    /// The network interface(s) to block ips from. To block on all interfaces use '--ifaces all'
    #[arg(long, short, required = true, num_args=1..)]
    pub ifaces: Vec<String>,
}

#[derive(Args, Debug)]
pub struct BlockArgs {
    /// IP(s) or IP range(s) to block. Ranges should be in CIDR notation eg 10.2.2.0/24
    #[arg(required = true, num_args=1..)]
    pub ips: Vec<String>,
}

#[derive(Args, Debug)]
pub struct UnBlockArgs {
    /// IP(s) or IP range(s) to unblock. Ranges should be in CIDR notation eg 10.2.2.0/24
    #[arg(required = true, num_args=1..)]
    pub ips: Vec<String>,
}

#[derive(Args, Debug)]
pub struct ListArgs {
    /// List only blocked IPv4 addresses.
    #[arg(short = '4', long)]
    pub ip4: bool,

    /// List only blocked IPv6 addresses.
    #[arg(short = '6', long)]
    pub ip6: bool,
}
