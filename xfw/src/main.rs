use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use xfw::{commands::run_command, util::argparser};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opts = argparser::Xfw::parse();

    env_logger::init();

    set_rlimit();

    let mut ebpf = init_ebpf()?;

    run_logger(&mut ebpf)?;

    run_command(opts, &mut ebpf).await?;

    Ok(())
}

fn set_rlimit() {
    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }
}

fn init_ebpf() -> Result<aya::Ebpf, aya::EbpfError> {
    // This will include the eBPF object file as raw bytes at compile-time and load it at
    // runtime.
    aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/xfw"
    )))
}

fn run_logger(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    match aya_log::EbpfLogger::init(ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
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
