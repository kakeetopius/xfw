use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
    str::FromStr,
};

use anyhow::{Context, anyhow};
use aya::{
    Ebpf,
    maps::{
        Map, MapData,
        lpm_trie::{Key, LpmTrie},
    },
    programs::{Xdp, XdpMode},
};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use tokio::signal;
use xfw_common::{
    types::{IPv4Addr, IPv4Key, IPv6Addr, IPv6Key},
    vars::{BLOCKED_IPV4_MAP_FILE, BLOCKED_IPV6_MAP_FILE, PROG_NAME},
};

use crate::util::argparser::{BlockArgs, Commands, ListArgs, StartArgs, Xfw};

pub async fn run_command(opts: Xfw, ebpf: &mut Ebpf, map_dir: &Path) -> anyhow::Result<()> {
    match opts.command {
        Commands::Start(args) => {
            run_start(args, ebpf).await?;
            Ok(())
        }
        Commands::Block(args) => run_block_ips(args, map_dir),
        Commands::List(args) => run_list(args, map_dir),
        _ => Ok(()),
    }
}

async fn run_start(opts: StartArgs, ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let program: &mut Xdp = ebpf
        .program_mut(PROG_NAME)
        .ok_or(anyhow!("could not load ebpf program: wrong program name"))?
        .try_into()?;

    program.load()?;

    if opts.ifaces.is_empty() {
        return Err(anyhow!(
            "Please provide one or more interfaces. If IP blocking on all interfaces is required use 'xfw block --ifaces all'"
        ));
    }

    let net_ifaces = if opts.ifaces[0] == "all" {
        netdev::get_interfaces()
            .into_iter()
            .map(|netiface| netiface.name)
            .collect()
    } else {
        opts.ifaces
    };

    for iface in net_ifaces {
        program.attach(&iface, XdpMode::default()).context(format!(
            "failed to attach the XDP program with default mode on interface: {}",
            iface
        ))?;
    }

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}

fn run_block_ips(opts: BlockArgs, map_dir: &Path) -> anyhow::Result<()> {
    let mut ip4addrs: Vec<IPv4Key> = Vec::new();
    let mut ip6addrs: Vec<IPv6Key> = Vec::new();

    for ip in opts.ips {
        if ip.contains("/") {
            match IpNet::from_str(&ip)? {
                IpNet::V4(ip4net) => {
                    ip4addrs.push(IPv4Key {
                        prefix: ip4net.prefix_len() as u32,
                        addr: ip4net.addr().as_octets().to_owned(),
                    });
                }
                IpNet::V6(ip6net) => {
                    ip6addrs.push(IPv6Key {
                        prefix: ip6net.prefix_len() as u32,
                        addr: ip6net.addr().as_octets().to_owned(),
                    });
                }
            }
        } else {
            match IpAddr::from_str(&ip)? {
                IpAddr::V4(ip4addr) => {
                    ip4addrs.push(IPv4Key {
                        prefix: 32,
                        addr: ip4addr.as_octets().to_owned(),
                    });
                }
                IpAddr::V6(ip6addr) => {
                    ip6addrs.push(IPv6Key {
                        prefix: 128,
                        addr: ip6addr.as_octets().to_owned(),
                    });
                }
            }
        }
    }

    insert_into_ip4_blocked_list(ip4addrs, map_dir)?;
    insert_into_ip6_blocked_list(ip6addrs, map_dir)?;

    Ok(())
}

fn run_list(opts: ListArgs, map_dir: &Path) -> anyhow::Result<()> {
    let blocked_ips = if opts.ip4 {
        get_blocked_ip4(map_dir)?
    } else if opts.ip6 {
        get_blocked_ip6(map_dir)?
    } else {
        let mut ips = get_blocked_ip4(map_dir)?;
        ips.extend(get_blocked_ip6(map_dir)?);
        ips
    };

    println!();
    for ip in blocked_ips {
        println!("{}", ip);
    }

    Ok(())
}

fn insert_into_ip4_blocked_list(ips: Vec<IPv4Key>, map_dir: &Path) -> anyhow::Result<()> {
    if ips.is_empty() {
        return Ok(());
    }

    let map = Map::from_map_data(MapData::from_pin(map_dir.join(BLOCKED_IPV4_MAP_FILE))?)?;

    let mut ip4map: LpmTrie<_, IPv4Addr, u32> = LpmTrie::try_from(map)?;

    for ip in ips {
        ip4map.insert(&Key::new(ip.prefix, ip.addr), 0, 0)?;
    }

    Ok(())
}

fn insert_into_ip6_blocked_list(ips: Vec<IPv6Key>, map_dir: &Path) -> anyhow::Result<()> {
    if ips.is_empty() {
        return Ok(());
    }

    let map = Map::from_map_data(MapData::from_pin(map_dir.join(BLOCKED_IPV6_MAP_FILE))?)?;

    let mut ip6map: LpmTrie<_, IPv6Addr, u32> = LpmTrie::try_from(map)?;

    for ip in ips {
        ip6map.insert(&Key::new(ip.prefix, ip.addr), 0, 0)?;
    }

    Ok(())
}

fn get_blocked_ip4(map_dir: &Path) -> anyhow::Result<Vec<IpNet>> {
    let map = Map::from_map_data(MapData::from_pin(map_dir.join(BLOCKED_IPV4_MAP_FILE))?)?;
    let ip4map: LpmTrie<_, IPv4Addr, u32> = LpmTrie::try_from(map)?;

    let mut ips: Vec<IpNet> = Vec::new();

    for ip4 in ip4map.iter() {
        let ip4_addr = match ip4 {
            Ok((addr_bytes, _)) => Ipv4Net::new(
                Ipv4Addr::from_octets(addr_bytes.data()),
                addr_bytes.prefix_len() as u8,
            )?,
            _ => continue,
        };

        ips.push(IpNet::V4(ip4_addr));
    }

    Ok(ips)
}

fn get_blocked_ip6(map_dir: &Path) -> anyhow::Result<Vec<IpNet>> {
    let map = Map::from_map_data(MapData::from_pin(map_dir.join(BLOCKED_IPV6_MAP_FILE))?)?;
    let ip6map: LpmTrie<_, IPv6Addr, u32> = LpmTrie::try_from(map)?;

    let mut ips: Vec<IpNet> = Vec::new();

    for ip6 in ip6map.iter() {
        let ip6_addr = match ip6 {
            Ok((addr_bytes, _)) => Ipv6Net::new(
                Ipv6Addr::from_octets(addr_bytes.data()),
                addr_bytes.prefix_len() as u8,
            )?,
            _ => continue,
        };

        ips.push(IpNet::V6(ip6_addr));
    }

    Ok(ips)
}
