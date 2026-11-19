//! Runs a mock server from a scenario file until Ctrl-C.

use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let (Some(kind), Some(path)) = (args.get(1), args.get(2)) else {
        eprintln!("usage: fortino-mock fortigate <scenario.yaml> [--bind ADDR:PORT]");
        return ExitCode::from(2);
    };
    if kind != "fortigate" {
        eprintln!("unknown mock kind {kind}");
        return ExitCode::from(2);
    }
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("read {path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let sc = match fortino_mock::fortigate::Scenario::from_yaml(&text) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let bind = args
        .iter()
        .position(|a| a == "--bind")
        .and_then(|i| args.get(i + 1))
        .and_then(|b| b.parse::<std::net::SocketAddr>().ok());
    let started = match bind {
        Some(b) => fortino_mock::fortigate::start_on(&sc, b).await,
        None => fortino_mock::fortigate::start(&sc).await,
    };
    let h = match started {
        Ok(h) => h,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    println!("listening on {} cert-sha256 {}", h.addr, h.cert_sha256);
    let _ = tokio::signal::ctrl_c().await;
    ExitCode::SUCCESS
}
