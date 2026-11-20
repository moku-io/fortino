//! The production tunnel worker as a standalone binary (see [`fortino_sslvpn::worker_main`]).

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<()> {
    fortino_sslvpn::worker_main::run().await
}
