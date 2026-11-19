# OpenFortiClient

OpenFortiClient is an open-source reimplementation of FortiClient, starting with its macOS VPN client. The first release will let users create or import a FortiGate SSL VPN profile, connect with a password and one-time code, see connection status, and disconnect using either the desktop app or the headless command-line client (`ofctl`). Both use the same background service. A headless installation needs only the CLI and service, and the VPN stays connected after the terminal closes. The maintainer is authorized to use both target gateways, GATEWAY-1 and GATEWAY-2. Both deployments will officially support OpenFortiClient. Each gateway has its own FortiClient Enterprise Management Server (EMS). Users will be able to set its address directly in the gateway’s profile.

**Build status:** milestone 2 runs against a fake tunnel. The daemon (`ofcd`) owns a SQLite profile store, authenticates local peers by kernel credentials, serializes the single VPN session and applies journaled network changes to a fake platform. `ofctl` and the macOS menu-bar app (`apps/macos`) create, import, connect, answer password/OTP prompts, show status and disconnect through the same socket protocol. The production worker adapter (openfortivpn) and the macOS network controller are not implemented, so the daemon does not create a real tunnel yet. Milestone 1 ran the pinned stock openfortivpn by hand against one gateway (GATEWAY-3): PPP completed IPCP and carried HTTPS to a private host. See [the backlog].

## Start here

| Decision | Project reference |
| --- | --- |
| What did FortiClient and the independent client actually do on each target? | [Session evidence and limits] |
| Which work comes first and what counts as success? | [Delivery and verification queue] |
| Who owns the tunnel, network state, credentials, CLI and menu? | [Client contracts] |
| How do we integrate PPP and test a real connection? | [Worker and macOS networking] |
| What must the worker adapter speak to the daemon? | [Worker channel protocol] |
| How does profile import work? | [XML import contract and fixtures] |
| How do I run and test the daemon, CLI and app locally? | [Development] |
| Which product observations can we reproduce offline? | [Desktop interface] and [native evidence ledger] |
| Where did these decisions come from? | [Source revisions and integration decisions] |

The first delivery target is GATEWAY-2 on Apple Silicon and macOS 15. An independent session reached PPP IPv4 negotiation there. Evaluate the pinned openfortivpn worker against that configuration before investing in a new wire implementation. On GATEWAY-1, the next step is to complete the device checks consistently, then test PPP. Both targets have separate acceptance records.

## Build and try it

Use stable Rust and the checked-in lockfile from the repository root.

```sh
cargo build --locked --workspace
cargo test --locked --workspace
```

Run the development daemon with the fake worker (unprivileged, no network changes) and drive it from the CLI or the app. See [development] for details.

```sh
cargo run -p ofcd -- --config fixtures/dev/ofcd-fake.toml   # allowed_uids must list your UID
export OFCTL_SOCKET=$PWD/target/dev/ofcd.sock
cargo run -p ofc-cli -- profile add GATEWAY-2 --host vpn.example.org --ems-server ems.example.org:9016
cargo run -p ofc-cli -- connect GATEWAY-2        # password hunter2, code 123456
OFC_SOCKET=$OFCTL_SOCKET swift run --package-path apps/macos OpenFortiClient
```

The synthetic TLS gateway still runs with `cargo run --locked -p ofc-mock -- fortigate fixtures/mock/basic.yaml`.

Project code is licensed under [GPL-3.0-or-later](LICENSE).
