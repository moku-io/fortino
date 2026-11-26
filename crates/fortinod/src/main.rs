//! `fortinod` entry point.

use std::path::PathBuf;
use std::process::ExitCode;

use fortino_core::proto::LogLevel;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, reload};

fn main() -> ExitCode {
    // `fortinod --worker`: one tunnel worker session, started by the daemon itself with the
    // channel on stdin. The installed app ships one root binary, verified by launchd.
    if std::env::args().nth(1).as_deref() == Some("--worker") {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build();
        return match rt.map(|rt| rt.block_on(fortino_sslvpn::worker_main::run())) {
            Ok(Ok(())) => ExitCode::SUCCESS,
            _ => ExitCode::FAILURE,
        };
    }
    match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt.block_on(daemon()),
        Err(e) => {
            eprintln!("fortinod: runtime: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn daemon() -> ExitCode {
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
    let mut config: Option<PathBuf> = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--config" | "-c" => match args.next() {
                Some(p) => config = Some(PathBuf::from(p)),
                None => {
                    eprintln!("--config needs a path");
                    return ExitCode::from(2);
                }
            },
            "--help" | "-h" => {
                println!(
                    "usage: fortinod [--config FILE]\n\
                     Without --config, reads {} if present, otherwise built-in defaults.",
                    fortinod::config::DEFAULT_CONFIG
                );
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("unknown argument {other}");
                return ExitCode::from(2);
            }
        }
    }
    let cfg = match fortinod::config::DaemonConfig::load_or_default(config.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("fortinod: {e}");
            return ExitCode::FAILURE;
        }
    };
    fortinod::logctl::restore(
        cfg.state_dir.join(fortinod::logctl::FILE_NAME),
        env.is_some(),
    );
    let run = async {
        let auth = fortinod::build_authorizer(&cfg)?;
        let session = fortinod::build_session(&cfg)?;
        let listener = fortinod::bind_socket(&cfg.socket_path, cfg.socket_group.as_deref())?;
        tracing::info!(socket = %cfg.socket_path.display(), "listening");
        // launchd stops the service with SIGTERM.
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .map_err(|e| format!("SIGTERM handler: {e}"))?;
        let restart = session.clone();
        let stopping = session.clone();
        tokio::select! {
            () = fortinod::server::serve(listener, session, auth) => {}
            // Stop a connected VPN and undo its routes, DNS and IPv6 block before exiting:
            // after an uninstall or a bootout nothing would restore them until a reboot.
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("shutting down");
                stopping.shutdown().await;
            }
            _ = term.recv() => {
                tracing::info!("shutting down");
                stopping.shutdown().await;
            }
            () = restart.exit_requested() => {
                // No attempt is active. Let the connection tasks deliver the answer to
                // `daemon.restart`, then exit; launchd (KeepAlive) starts the installed binary.
                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                tracing::info!("exiting for restart");
            }
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
