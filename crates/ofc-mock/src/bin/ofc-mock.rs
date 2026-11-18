//! Runs a mock server from a scenario file until Ctrl-C.

use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let (Some(kind), Some(path)) = (args.get(1), args.get(2)) else {
        eprintln!("usage: ofc-mock fortigate <scenario.yaml>");
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
    let sc = match ofc_mock::fortigate::Scenario::from_yaml(&text) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let h = match ofc_mock::fortigate::start(&sc).await {
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
