//! `ofcd` entry point.

use std::path::PathBuf;
use std::process::ExitCode;

use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with_writer(|| ofc_secret::RedactingWriter::new(std::io::stderr()))
        .init();

    let mut args = std::env::args().skip(1);
    let mut config = PathBuf::from(ofcd::config::DEFAULT_CONFIG);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--config" | "-c" => match args.next() {
                Some(p) => config = PathBuf::from(p),
                None => {
                    eprintln!("--config needs a path");
                    return ExitCode::from(2);
                }
            },
            "--help" | "-h" => {
                println!("usage: ofcd [--config FILE]");
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("unknown argument {other}");
                return ExitCode::from(2);
            }
        }
    }
    let cfg = match ofcd::config::DaemonConfig::load(&config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ofcd: {e}");
            return ExitCode::FAILURE;
        }
    };
    let run = async {
        let auth = ofcd::build_authorizer(&cfg)?;
        let session = ofcd::build_session(&cfg)?;
        let listener = ofcd::bind_socket(&cfg.socket_path, cfg.socket_group.as_deref())?;
        tracing::info!(socket = %cfg.socket_path.display(), "listening");
        tokio::select! {
            () = ofcd::server::serve(listener, session, auth) => {}
            _ = tokio::signal::ctrl_c() => tracing::info!("shutting down"),
        }
        Ok::<(), String>(())
    };
    match run.await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ofcd: {e}");
            ExitCode::FAILURE
        }
    }
}
