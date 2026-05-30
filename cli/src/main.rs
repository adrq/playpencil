use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "playpencil")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the sandbox daemon
    Serve {
        /// TCP port to listen on
        #[arg(long, default_value = "7070")]
        port: u16,

        /// Bind address
        #[arg(long, default_value = "127.0.0.1")]
        bind: String,

        /// Data directory for sandbox state
        #[arg(long)]
        data_dir: PathBuf,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Serve {
            port,
            bind,
            data_dir,
        }) => run_serve(port, bind, data_dir),
        None => {
            println!("playpencil v{}", playpencil_core::version());
            Ok(())
        }
    }
}

#[cfg(target_os = "linux")]
fn run_serve(port: u16, bind: String, data_dir: PathBuf) -> anyhow::Result<()> {
    use std::sync::Arc;

    use playpencil_core::backend::libkrun::LibkrunBackend;
    use playpencil_core::rootfs::linux::LinuxRootfsProvider;

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    std::fs::create_dir_all(&data_dir)?;

    let exe = std::env::current_exe()?;
    let exe_dir = exe
        .parent()
        .ok_or_else(|| anyhow::anyhow!("cannot determine executable directory"))?;
    let init_binary = exe_dir.join("playpencil-init");
    if !init_binary.exists() {
        anyhow::bail!(
            "playpencil-init not found at {}. Run 'make all' first.",
            init_binary.display()
        );
    }

    let ip: std::net::IpAddr = bind
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid bind address: {e}"))?;
    let bind_addr = std::net::SocketAddr::new(ip, port);

    let rootfs_provider = Arc::new(LinuxRootfsProvider);
    let backend = LibkrunBackend::new(&data_dir, &init_binary, rootfs_provider)
        .map_err(|e| anyhow::anyhow!("failed to initialize backend: {e}"))?;

    let config = playpencil_server::ServerConfig { bind_addr };

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(playpencil_server::run_server(config, backend))?;

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn run_serve(_port: u16, _bind: String, _data_dir: PathBuf) -> anyhow::Result<()> {
    anyhow::bail!("serve is only supported on Linux");
}
