use anyhow::{Context, anyhow};
use aya::{
    Ebpf,
    programs::{Xdp, XdpMode},
};
use tokio::signal;

use crate::util::argparser::{Commands, StartArgs, Xfw};

pub async fn run_command(opts: Xfw, ebpf: &mut Ebpf) -> anyhow::Result<()> {
    match opts.command {
        Commands::Start(args) => {
            run_start(args, ebpf).await?;
            Ok(())
        }
        _ => Ok(()),
    }
}

async fn run_start(opts: StartArgs, ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let program: &mut Xdp = ebpf.program_mut("xfw").unwrap().try_into()?;
    program.load()?;

    if opts.ifaces.is_empty() {
        return Err(anyhow!(
            "Please provide on or more interfaces. If blocking on all interfaces is required use 'xfw block --ifaces all'"
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
