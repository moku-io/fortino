# Notes for coding agents

Fortino is a independent, native reimplementation of FortiClient (macOS first): SSL VPN, then EMS. Read [README.md](README.md) for the goal and status and [the design notes] for what comes next. These rules are the ones that are easy to break without knowing the history.

## Truthfulness and truthfulness

- Code comments explain what goes on the wire and why. Never copy vendor code, Fortinet binaries, keys, certificates, assets or long vendor strings into the repository. Protocol tokens (paths, header and field names) are fine.
- Anything inferred rather than observed carries an `UNVERIFIED` comment in code and an `(UNVERIFIED)` tag in docs, and must match the mock's assumption.
- Wire identity may match FortiClient (headers, order, frame layouts). Posture never lies: no claimed AV, firewall, host-check result or EMS feature the client doesn't have. Don't present an EMS serial unless this client is registered to that EMS.

## Secrets and deployment data

- Never print, log, commit or copy passwords, OTPs, session cookies (`SVPNCOOKIE`, `SVPNTMPCOOKIE`), EMS keys or credentials-file values. Debug logging records status codes, cookie names and paths only.
- Real gateway names, addresses, site labels, usernames and captures stay out of the repository. Refer to gateways as GATEWAY-1, GATEWAY-2, … Fixtures are synthetic.
- For live tests the maintainer may provide a credentials file outside the repository; how to use it is in [the design notes]. Inspect it only by key names, never by printing its values.

## Root and the host network

- Never run anything that changes routes, DNS, pf or interfaces as root on the development Mac. Use the disposable Tart VM (`scripts/macos-vm-test.sh`, [the design notes]).
- `ofc-sslvpn-probe` with its default in-memory device needs no root and changes nothing on the host; prefer it for live gateway checks.

## Code

- Rust workspace, edition 2024. `unsafe` is denied; `unwrap`, `expect` and `panic` are denied outside tests (integration tests opt out with `#![allow(...)]`).
- Protocol crates (`ofc-proto-*`) are sans-IO and fuzz-safe: every parser gets a property test that it never panics. Bound every collection and frame size from the network.
- Before finishing: `cargo fmt --all`, `cargo clippy --workspace --all-targets` with no warnings, `cargo test --workspace`. The Swift app builds with `swift build --package-path apps/macos`.
- When behaviour changes, update the doc that owns it (see the table in the README) and record live results in the backlog under gateway aliases.
