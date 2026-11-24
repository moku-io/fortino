# Notes for coding agents

Fortino is a native client for FortiGate SSL VPN and FortiClient EMS (macOS first, Linux next). Read [README.md](README.md) for the goal and status and [DEVELOPMENT.md](DEVELOPMENT.md) for how to build and test. These rules are the ones that are easy to break without knowing the history.

## Truthfulness

- Anything inferred rather than observed carries an `UNVERIFIED` comment in code and must match the mock's assumption.
- Code comments explain what goes on the wire and why, never where it was learned (no client versions, component names or symbols). Never copy vendor code, binaries, keys, certificates, assets or long vendor strings into the repository. Protocol tokens (paths, header and field names) are fine.
- Each VPN profile names its own EMS server; registrations are kept per EMS and the one used follows the profile being connected. Never design an EMS flow that requires unregistering to switch gateways.
- Wire identity may match FortiClient (headers, order, frame layouts). Posture never lies: no claimed AV, firewall, host-check result or EMS feature the client doesn't have. Don't present an EMS serial unless this client is registered to that EMS.

## Secrets and deployment data

- Never print, log, commit or copy passwords, OTPs, session cookies (`SVPNCOOKIE`, `SVPNTMPCOOKIE`), EMS keys or credentials-file values. Debug logging records status codes, cookie names and paths only.
- Real gateway names, addresses, site labels, usernames and captures stay out of the repository. Use synthetic fixtures and example domains in documentation.
- For live tests the maintainer may provide a credentials file outside the repository ([DEVELOPMENT.md](DEVELOPMENT.md#against-a-real-gateway)). Inspect it only by key names, never by printing its values.

## Root and the host network

- Never run anything that changes routes, DNS, pf or interfaces as root on the development Mac. Use the disposable Tart VM (`scripts/macos-vm-test.sh`, [DEVELOPMENT.md](DEVELOPMENT.md#root-tests-in-a-disposable-macos-vm)).
- `fortino-sslvpn-probe` with its default in-memory device needs no root and changes nothing on the host; prefer it for live gateway checks.

## Desktop app

- Modern, clean, native macOS: standard SwiftUI/AppKit controls and the Human Interface Guidelines, easy to use. Never copy FortiClient's interface; wire parity is for the protocol only.

## Portability

- Linux will follow macOS. Keep platform code behind `NetPlatform`, `DeviceFactory` and `CredentialStore`; shared crates must not use macOS-only APIs.
- Saved passwords live in the user's secret store, handled by the CLI, never by the root daemon.

## Code

- Rust workspace, edition 2024. `unsafe` is denied; `unwrap`, `expect` and `panic` are denied outside tests (integration tests opt out with `#![allow(...)]`).
- Protocol crates (`fortino-proto-*`) are sans-IO and fuzz-safe: every parser gets a property test that it never panics. Bound every collection and frame size from the network.
- Before finishing: `cargo fmt --all`, `cargo clippy --workspace --all-targets` with no warnings, `cargo test --workspace`. The Swift app builds with `swift build --package-path apps/macos`.
- When user-visible behaviour changes, update README.md or DEVELOPMENT.md.
