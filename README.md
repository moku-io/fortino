# OpenFortiClient

OpenFortiClient is an open-source reimplementation of FortiClient, starting with its macOS VPN client. The first release will let users create or import a FortiGate SSL VPN profile, connect with a password and one-time code, see connection status, and disconnect using either the desktop app or the headless command-line client (`ofctl`). Both use the same background service. A headless installation needs only the CLI and service, and the VPN stays connected after the terminal closes. The maintainer is authorized to use both target gateways, GATEWAY-1 and GATEWAY-2. Both deployments will officially support OpenFortiClient. Each gateway has its own FortiClient Enterprise Management Server (EMS). Users will be able to set its address directly in the gateway’s profile.

**Build status:** the Rust workspace contains a synthetic TLS gateway, secret handling, a fake network platform and a file-backed rollback journal. The desktop UI, daemon and CLI are at the scaffolding stage. The production worker adapter, macOS network controller and profile importer are planned. Neither target has passed an independent end-to-end traffic test.

## Start here

| Decision | Project reference |
| --- | --- |
| What did FortiClient and the independent client actually do on each target? | [Session evidence and limits] |
| Which work comes first and what counts as success? | [Delivery and verification queue] |
| Who owns the tunnel, network state, credentials, CLI and menu? | [Client contracts] |
| How do we integrate PPP and test a real connection? | [Worker and macOS networking] |
| How does profile import work? | [XML import contract and fixtures] |
| Which product observations can we reproduce offline? | [Desktop interface] and [native evidence ledger] |
| Where did these decisions come from? | [Source revisions and integration decisions] |

The first delivery target is GATEWAY-2 on Apple Silicon and macOS 15. An independent session reached PPP IPv4 negotiation there. Evaluate the pinned openfortivpn worker against that configuration before investing in a new wire implementation. On GATEWAY-1, the next step is to complete the device checks consistently, then test PPP. Both targets have separate acceptance records.

## Build the foundations

Use stable Rust and the checked-in lockfile from the repository root.

```sh
cargo build --locked --workspace
cargo test --locked --workspace
cargo run --locked -p ofc-mock -- fortigate fixtures/mock/basic.yaml
```

The last command starts the synthetic server on an ephemeral loopback port. The TLS integration test also requires permission to bind loopback. The current mock serves the gateway information response. The planned `ofctl` commands and their completion semantics are in the client contract.

Project code is licensed under [GPL-3.0-or-later](LICENSE).
