use std::path::{Path, PathBuf};

use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use anyhow::Context;
use xfw::{commands::run_command, util::argparser};
use xfw_common::vars::{
    BLOCKED_IPV4_MAP_FILE, BLOCKED_IPV4_MAP_NAME, BLOCKED_IPV6_MAP_FILE, BLOCKED_IPV6_MAP_NAME,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opts = argparser::Xfw::parse();

    env_logger::init();

    set_rlimit();

    let map_dir = get_map_dir(&opts.maps_dir)?;

    let mut ebpf = init_ebpf(&map_dir)?;

    run_logger(&mut ebpf)?;

    run_command(opts, &mut ebpf, &map_dir).await?;

    Ok(())
}

fn set_rlimit() {
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

fn init_ebpf(map_dir: &Path) -> Result<aya::Ebpf, aya::EbpfError> {
    let mut loader = aya::EbpfLoader::new();

    loader
        .map_pin_path(BLOCKED_IPV4_MAP_NAME, map_dir.join(BLOCKED_IPV4_MAP_FILE))
        .map_pin_path(BLOCKED_IPV6_MAP_NAME, map_dir.join(BLOCKED_IPV6_MAP_FILE))
        .load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/xfw"
        )))
}

fn run_logger(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
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

fn get_map_dir(dir: &Option<String>) -> anyhow::Result<PathBuf> {
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
