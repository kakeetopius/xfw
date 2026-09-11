use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
};

use anyhow::Context;
use aya::maps::{
    Map, MapData, MapError,
    lpm_trie::{Key, LpmTrie},
};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use log::{debug, warn};
use xfw_common::{
    types::{IPKey, IPv4Addr, IPv4Key, IPv6Addr, IPv6Key},
    vars::{
        BLOCKED_IPV4_MAP_FILE, BLOCKED_IPV4_MAP_NAME, BLOCKED_IPV6_MAP_FILE, BLOCKED_IPV6_MAP_NAME,
    },
};

pub fn insert_into_ip4_blocked_list(ips: Vec<IPv4Key>, map_dir: &Path) -> anyhow::Result<()> {
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

pub fn insert_into_ip6_blocked_list(ips: Vec<IPv6Key>, map_dir: &Path) -> anyhow::Result<()> {
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

pub fn delete_from_ip4_blocked_list(
    ips: Vec<IPv4Key>,
    map_dir: &Path,
) -> anyhow::Result<Vec<IPKey>> {
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

pub fn delete_from_ip6_blocked_list(
    ips: Vec<IPv6Key>,
    map_dir: &Path,
) -> anyhow::Result<Vec<IPKey>> {
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

pub fn get_all_blocked_ip4(map_dir: &Path) -> anyhow::Result<Vec<IPv4Key>> {
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

pub fn get_all_blocked_ip6(map_dir: &Path) -> anyhow::Result<Vec<IPv6Key>> {
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

pub fn get_all_blocked_ip4_as_ipnets(map_dir: &Path) -> anyhow::Result<Vec<IpNet>> {
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

pub fn get_all_blocked_ip6_as_ipnets(map_dir: &Path) -> anyhow::Result<Vec<IpNet>> {
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

pub fn set_rlimit() {
    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }
}

pub fn init(map_dir: &Path) -> Result<aya::Ebpf, aya::EbpfError> {
    let mut loader = aya::EbpfLoader::new();

    loader
        .map_pin_path(BLOCKED_IPV4_MAP_NAME, map_dir.join(BLOCKED_IPV4_MAP_FILE))
        .map_pin_path(BLOCKED_IPV6_MAP_NAME, map_dir.join(BLOCKED_IPV6_MAP_FILE))
        .load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/xfw"
        )))
}

pub fn run_logger(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    match aya_log::EbpfLogger::init(ebpf) {
        Err(e) => {
            // This can happen if all log statements from the eBPF program
            warn!("failed to initialize eBPF logger: {e}");
            Ok(())
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;

            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });

            Ok(())
        }
    }
}

pub fn get_map_dir(dir: &Option<String>) -> anyhow::Result<PathBuf> {
    let map_dir = match dir {
        Some(path) => PathBuf::from(path),
        None => PathBuf::from("/sys").join("fs").join("bpf"),
    };

    std::fs::create_dir_all(&map_dir).context(format!(
        "Failed to create the map directory: {}",
        map_dir.to_str().unwrap_or("")
    ))?;

    Ok(map_dir)
}
