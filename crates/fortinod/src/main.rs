//! `fortinod` entry point.

use std::path::PathBuf;
use std::process::ExitCode;

use fortino_core::proto::LogLevel;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, reload};

#[tokio::main]
async fn main() -> ExitCode {
    let env = std::env::var("RUST_LOG").ok();
    let initial = env.as_deref().map_or(Some(LogLevel::Info), LogLevel::parse);
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    let (filter, handle) = reload::Layer::new(filter);
    tracing_subscriber::registry()
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(|| fortino_secret::RedactingWriter::new(std::io::stderr())),
        )
        .init();
    fortinod::logctl::install(
        Box::new(move |level| {
            handle
                .reload(EnvFilter::new(level))
                .map_err(|e| e.to_string())
        }),
        initial,
    );

    let mut args = std::env::args().skip(1);
    let mut config = PathBuf::from(fortinod::config::DEFAULT_CONFIG);
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
                println!("usage: fortinod [--config FILE]");
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("unknown argument {other}");
                return ExitCode::from(2);
            }
        }
    }
    let cfg = match fortinod::config::DaemonConfig::load(&config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("fortinod: {e}");
            return ExitCode::FAILURE;
        }
    };
    let run = async {
        let auth = fortinod::build_authorizer(&cfg)?;
        let session = fortinod::build_session(&cfg)?;
        let listener = fortinod::bind_socket(&cfg.socket_path, cfg.socket_group.as_deref())?;
        tracing::info!(socket = %cfg.socket_path.display(), "listening");
        // launchd stops the service with SIGTERM.
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .map_err(|e| format!("SIGTERM handler: {e}"))?;
        tokio::select! {
            () = fortinod::server::serve(listener, session, auth) => {}
            _ = tokio::signal::ctrl_c() => tracing::info!("shutting down"),
            _ = term.recv() => tracing::info!("shutting down"),
        }
        Ok::<(), String>(())
    };
    match run.await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("fortinod: {e}");
            ExitCode::FAILURE
        }
    }
}
