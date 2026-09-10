use std::{
    fs::{self, File},
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
    str::FromStr,
};

use anyhow::{Context, anyhow};
use aya::{
    Ebpf,
    maps::{
        Map, MapData, MapError,
        lpm_trie::{Key, LpmTrie},
    },
    programs::{Xdp, XdpMode},
};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use tokio::signal;
use xfw_common::{
    types::{IPKey, IPv4Addr, IPv4Key, IPv6Addr, IPv6Key},
    vars::{BLOCKED_IPV4_MAP_FILE, BLOCKED_IPV6_MAP_FILE, PROG_NAME},
};

use crate::util::argparser::{
    BlockArgs, Commands, ExportArgs, ExportFormats, ListArgs, StartArgs, UnBlockArgs, Xfw,
};

pub async fn run_command(opts: Xfw, ebpf: &mut Ebpf, map_dir: &Path) -> anyhow::Result<()> {
    match opts.command {
        Commands::Start(args) => {
            run_start(args, ebpf).await?;
            Ok(())
        }
        Commands::Block(args) => run_block_ips(args, map_dir),
        Commands::Unblock(args) => run_unblock(args, map_dir),
        Commands::List(args) => run_list(args, map_dir),
        Commands::Export(args) => run_export(args, map_dir),
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
    println!("xfw started, use Ctrl-C to stop.");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}

fn run_block_ips(opts: BlockArgs, map_dir: &Path) -> anyhow::Result<()> {
    let (mut ip4addrs, mut ip6addrs) = get_ip_keys_from_strings(&opts.ips)?;

    if let Some(file_name) = opts.file {
        let mut ip_strings = String::new();

        File::open(&file_name)
            .context(format!("Failed to open file '{}'", file_name))?
            .read_to_string(&mut ip_strings)?;

        let file_ips: Vec<&str> = ip_strings
            // rustfmt: keep multi line pliz!!
            .split("\n")
            .filter(|s| !s.is_empty())
            .collect();

        let (file_ip4s, file_ip6s) = get_ip_keys_from_strings(&file_ips)?;

        ip4addrs.extend(file_ip4s);
        ip6addrs.extend(file_ip6s);
    }

    insert_into_ip4_blocked_list(ip4addrs, map_dir)?;
    insert_into_ip6_blocked_list(ip6addrs, map_dir)?;

    Ok(())
}

fn run_unblock(opts: UnBlockArgs, map_dir: &Path) -> anyhow::Result<()> {
    let (mut ip4addrs, mut ip6addrs) = get_ip_keys_from_strings(&opts.ips)?;

    if opts.unblock_all {
        ip4addrs.extend(get_all_blocked_ip4(map_dir)?);
        ip6addrs.extend(get_all_blocked_ip6(map_dir)?);
    }

    let mut successfully_unblocked = delete_from_ip4_blocked_list(ip4addrs, map_dir)?;
    successfully_unblocked.extend(delete_from_ip6_blocked_list(ip6addrs, map_dir)?);

    if !successfully_unblocked.is_empty() {
        println!("\nUnblocked: ");

        let ip_strings: Vec<String> = successfully_unblocked
            .into_iter()
            .map(|ip| ip_key_to_string(ip).unwrap_or("".to_string()))
            .collect();

        println!("{}", ip_strings.join(", "))
    }

    Ok(())
}

fn run_list(opts: ListArgs, map_dir: &Path) -> anyhow::Result<()> {
    let blocked_ips = if opts.ip4 {
        get_all_blocked_ip4_as_ipnets(map_dir)?
    } else if opts.ip6 {
        get_all_blocked_ip6_as_ipnets(map_dir)?
    } else {
        let mut ips = get_all_blocked_ip4_as_ipnets(map_dir)?;
        ips.extend(get_all_blocked_ip6_as_ipnets(map_dir)?);
        ips
    };

    println!();
    for ip in blocked_ips {
        println!("{}", ip);
    }

    Ok(())
}

fn run_export(opts: ExportArgs, map_dir: &Path) -> anyhow::Result<()> {
    let mut ips = get_all_blocked_ip4_as_ipnets(map_dir)?;
    let ip6s = get_all_blocked_ip6_as_ipnets(map_dir)?;
    ips.extend(ip6s);

    let mut out: Box<dyn Write> = if let Some(file) = opts.output_file {
        let f = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(file)?;
        Box::new(f)
    } else {
        Box::new(io::stdout())
    };

    match opts.format {
        ExportFormats::Txt => export_txt(ips, &mut *out),
        ExportFormats::Json => export_json(ips, &mut *out),
        ExportFormats::List => export_list(ips, &mut *out),
    }
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

fn delete_from_ip4_blocked_list(ips: Vec<IPv4Key>, map_dir: &Path) -> anyhow::Result<Vec<IPKey>> {
    let mut successful: Vec<IPKey> = Vec::new();
    if ips.is_empty() {
        return Ok(successful);
    }

    let map = Map::from_map_data(MapData::from_pin(map_dir.join(BLOCKED_IPV4_MAP_FILE))?)?;
    let mut ip4map: LpmTrie<_, IPv4Addr, u32> = LpmTrie::try_from(map)?;

    for ip in ips {
        match ip4map.remove(&Key::new(ip.prefix, ip.addr)) {
            Ok(_) => successful.push(IPKey::V4(ip)),

            Err(map_error) => {
                if let MapError::SyscallError(e) = &map_error
                    && e.io_error.kind() == io::ErrorKind::NotFound
                {
                    continue; // ignore ips that are not found in the blocked list.
                } else {
                    return Err(map_error.into());
                }
            }
        }
    }

    Ok(successful)
}

fn delete_from_ip6_blocked_list(ips: Vec<IPv6Key>, map_dir: &Path) -> anyhow::Result<Vec<IPKey>> {
    let mut successful: Vec<IPKey> = Vec::new();
    if ips.is_empty() {
        return Ok(successful);
    }

    let map = Map::from_map_data(MapData::from_pin(map_dir.join(BLOCKED_IPV6_MAP_FILE))?)?;
    let mut ip6map: LpmTrie<_, IPv6Addr, u32> = LpmTrie::try_from(map)?;

    for ip in ips {
        match ip6map.remove(&Key::new(ip.prefix, ip.addr)) {
            Ok(_) => successful.push(IPKey::V6(ip)),
            Err(map_error) => {
                if let MapError::SyscallError(e) = &map_error
                    && e.io_error.kind() == io::ErrorKind::NotFound
                {
                    continue; // ignore ips that are not found in the blocked list.
                } else {
                    return Err(map_error.into());
                }
            }
        }
    }

    Ok(successful)
}

fn get_all_blocked_ip4(map_dir: &Path) -> anyhow::Result<Vec<IPv4Key>> {
    let mut ips: Vec<IPv4Key> = Vec::new();

    let map = Map::from_map_data(MapData::from_pin(map_dir.join(BLOCKED_IPV4_MAP_FILE))?)?;
    let ip4map: LpmTrie<_, IPv4Addr, u32> = LpmTrie::try_from(map)?;

    for ip4 in ip4map.iter() {
        let ip4_key = match ip4 {
            Ok((addr_bytes, _)) => IPv4Key {
                addr: addr_bytes.data(),
                prefix: addr_bytes.prefix_len(),
            },
            _ => continue,
        };

        ips.push(ip4_key);
    }

    Ok(ips)
}

fn get_all_blocked_ip6(map_dir: &Path) -> anyhow::Result<Vec<IPv6Key>> {
    let mut ips: Vec<IPv6Key> = Vec::new();

    let map = Map::from_map_data(MapData::from_pin(map_dir.join(BLOCKED_IPV6_MAP_FILE))?)?;
    let ip6map: LpmTrie<_, IPv6Addr, u32> = LpmTrie::try_from(map)?;

    for ip6 in ip6map.iter() {
        let ip6_key = match ip6 {
            Ok((addr_bytes, _)) => IPv6Key {
                addr: addr_bytes.data(),
                prefix: addr_bytes.prefix_len(),
            },
            _ => continue,
        };

        ips.push(ip6_key);
    }

    Ok(ips)
}

fn get_all_blocked_ip4_as_ipnets(map_dir: &Path) -> anyhow::Result<Vec<IpNet>> {
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

fn get_all_blocked_ip6_as_ipnets(map_dir: &Path) -> anyhow::Result<Vec<IpNet>> {
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

fn get_ip_keys_from_strings<S>(ips: &[S]) -> anyhow::Result<(Vec<IPv4Key>, Vec<IPv6Key>)>
where
    S: AsRef<str> + std::fmt::Display,
{
    let mut ip4addrs: Vec<IPv4Key> = Vec::new();
    let mut ip6addrs: Vec<IPv6Key> = Vec::new();

    for ip in ips {
        if ip.as_ref().contains("/") {
            match IpNet::from_str(ip.as_ref()) {
                Ok(IpNet::V4(ip4net)) => {
                    ip4addrs.push(IPv4Key {
                        prefix: ip4net.prefix_len() as u32,
                        addr: ip4net.network().as_octets().to_owned(),
                    });
                }
                Ok(IpNet::V6(ip6net)) => {
                    ip6addrs.push(IPv6Key {
                        prefix: ip6net.prefix_len() as u32,
                        addr: ip6net.network().as_octets().to_owned(),
                    });
                }
                Err(_) => return Err(anyhow!(format!("Invalid IP address '{}'", ip))),
            }
        } else {
            match IpAddr::from_str(ip.as_ref()) {
                Ok(IpAddr::V4(ip4addr)) => {
                    ip4addrs.push(IPv4Key {
                        prefix: 32,
                        addr: ip4addr.as_octets().to_owned(),
                    });
                }
                Ok(IpAddr::V6(ip6addr)) => {
                    ip6addrs.push(IPv6Key {
                        prefix: 128,
                        addr: ip6addr.as_octets().to_owned(),
                    });
                }
                Err(_) => return Err(anyhow!(format!("Invalid IP address '{}'", ip))),
            }
        }
    }

    Ok((ip4addrs, ip6addrs))
}

fn ip_key_to_string(ip_key: IPKey) -> anyhow::Result<String> {
    let ip = match ip_key {
        IPKey::V4(v4) => {
            let ip = Ipv4Net::new(Ipv4Addr::from_octets(v4.addr), v4.prefix as u8)?;
            IpNet::V4(ip)
        }
        IPKey::V6(v6) => {
            let ip = Ipv6Net::new(Ipv6Addr::from_octets(v6.addr), v6.prefix as u8)?;
            IpNet::V6(ip)
        }
    };

    Ok(ip.to_string())
}

fn export_txt<W>(ips: Vec<IpNet>, out: &mut W) -> anyhow::Result<()>
where
    W: Write + ?Sized,
{
    let ips_strings: Vec<String> = ips
        // rustfmt: pliz chill
        .iter()
        .map(|i| i.to_string())
        .collect();

    let ips_string = ips_strings.join("\n");

    std::io::copy(&mut ips_string.as_bytes(), out)?;

    Ok(())
}

fn export_json<W>(ips: Vec<IpNet>, out: &mut W) -> anyhow::Result<()>
where
    W: Write + ?Sized,
{
    serde_json::to_writer_pretty(out, &ips)?;

    Ok(())
}

fn export_list<W>(ips: Vec<IpNet>, out: &mut W) -> anyhow::Result<()>
where
    W: Write + ?Sized,
{
    let ip_list: Vec<String> = ips
        // rustfmt: pliz chill
        .iter()
        .map(|ip| ip.to_string())
        .collect();

    std::io::copy(&mut ip_list.join(", ").as_bytes(), out)?;

    Ok(())
}
