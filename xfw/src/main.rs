use clap::Parser;
use xfw::{commands::run_command, util::argparser};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opts = argparser::XfwArgs::parse();

    run_command(opts).await
}
