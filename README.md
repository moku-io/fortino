# Fortino

Fortino is an open-source, independent reimplementation of FortiClient, starting with its macOS VPN client. The goal is a native client that a FortiGate and its FortiClient Enterprise Management Server (EMS) can admit like the vendor client: SSL VPN login with password and one-time codes, the PPP and TUN tunnel modes, split routes and split DNS, the IPv6 block, and EMS registration with truthful posture. openfortivpn and OpenConnect cover the basic SSL VPN; neither speaks EMS or reproduces FortiClient's wire identity, which some gateways require before they admit a tunnel.

**Built for people who use more than one organization's VPN.** Each VPN profile names its own EMS server, and Fortino keeps a separate EMS registration for each. Connecting to a gateway uses that gateway's EMS, so switching between organizations needs no unregistering and re-registering, unlike FortiClient, which holds one EMS registration per machine.

**Scope of the first release.** Users create or import a FortiGate SSL VPN profile, connect with a password and one-time code, see the connection status and disconnect, from the macOS menu-bar app or the headless CLI (`fortino`). Both drive the same root service (`fortinod`), and the VPN stays up after the terminal closes. The maintainer is authorized to use the target gateways (GATEWAY-1 to GATEWAY-4), and the deployments will officially support Fortino. Each gateway has its own EMS, whose address is set in the gateway's profile.

**Build status.**

- The daemon, CLI and app work end to end against a fake tunnel (milestone 2): profile store, kernel-credential peer checks, one serialized session, journaled network changes, password/OTP prompts.
- The native SSL VPN worker (`crates/fortino-sslvpn`) has connected to a real gateway (GATEWAY-3) with its own PPP and carried TCP and ICMP through the tunnel, using an in-memory tun device. It is not yet wired to the daemon as a separate process, and the macOS network controller (routes, DNS, IPv6 block) has not yet run as root in a VM. See [the backlog].
- Not started: TUN tunnel mode, DTLS, the EMS agent and packaging.

## Start here

| Decision | Project reference |
| --- | --- |
| What did FortiClient and the independent client actually do on each target? | [Session evidence and limits] |
| Which work comes first and what counts as success? | [Delivery and verification queue] |
| Who owns the tunnel, network state, credentials, CLI and menu? | [Client contracts] |
| How do we integrate PPP and test a real connection? | [Worker and macOS networking] |
| What must a worker speak to the daemon? | [Worker channel protocol] |
| How does the EMS agent register, report and stay truthful? | [EMS agent] |
| How does Fortino differ from FortiClient on the wire (debugging a real deployment)? | [Differences from FortiClient] |
| Rules for coding agents | [AGENTS.md](AGENTS.md) |
| How does profile import work? | [XML import contract and fixtures] |
| How do I run and test the daemon, CLI and app locally? | [Development] |
| Which product observations can we reproduce offline? | [Desktop interface] and [native evidence ledger] |
| Where did these decisions come from? | [Source revisions and integration decisions] |

The first delivery target is GATEWAY-2 on Apple Silicon and macOS 15. GATEWAY-1 additionally requires the client's own EMS registration before it admits a tunnel, so the EMS agent follows the native SSL VPN worker. openfortivpn is kept only as a lab reference for comparing behaviour.

## Build and try it

Use stable Rust and the checked-in lockfile from the repository root.

```sh
cargo build --locked --workspace
cargo test --locked --workspace
```

Run the development daemon with the fake worker (unprivileged, no network changes) and drive it from the CLI or the app. See [development] for details.

```sh
cargo run -p fortinod -- --config fixtures/dev/fortinod-fake.toml   # allowed_uids must list your UID
export FORTINO_SOCKET=$PWD/target/dev/fortinod.sock
cargo run -p fortino-cli -- profile add GATEWAY-2 --host vpn.example.org --ems-server ems.example.org:9016
cargo run -p fortino-cli -- connect GATEWAY-2        # password hunter2, code 123456
swift run --package-path apps/macos Fortino
```

### Build the downloads

After changing the source, rebuild everything (Rust binaries, app bundle and DMG) with one command. The VPN service ships inside `Fortino.app`, and macOS only registers it from a Developer ID-signed app, so sign the build:

```sh
SIGN_APP="Developer ID Application: …" scripts/package-macos.sh   # → target/package/Fortino-<version>.dmg
scripts/macos-vm-dmg-test.sh   # optional: install it from the DMG in a disposable VM and test it
```

`security find-identity -v -p codesigning` prints the exact identity name for `SIGN_APP`. The first build asks to let the terminal control Finder (it lays out the DMG window); allow it in System Settings → Privacy & Security → Automation.

Users drag Fortino from the DMG to Applications, open it and allow its VPN service once in System Settings → General → Login Items; moving it to the Trash uninstalls it. The version comes from `CFBundleShortVersionString` in `apps/macos/Resources/Info.plist`; raise it (and `CFBundleVersion`) for each build you hand out. Profiles survive reinstalling. For what the bundle contains, configuration and notarization, see [development].

### Release checklist

1. Raise `CFBundleShortVersionString` and `CFBundleVersion` in `apps/macos/Resources/Info.plist`.
2. Check the tree:
   ```sh
   cargo fmt --all --check
   cargo clippy --workspace --all-targets
   cargo test --locked --workspace
   ```
3. Commit, so the DMG matches a commit.
4. Build the signed DMG (it builds the release binaries itself); add `NOTARY_PROFILE=fortino` once a notary profile exists:
   ```sh
   SIGN_APP="Developer ID Application: …" scripts/package-macos.sh
   ```
5. Optionally run `scripts/macos-vm-dmg-test.sh`, then tag the commit (`git tag v<version>`) and hand out `target/package/Fortino-<version>.dmg`.

The synthetic TLS gateway still runs with `cargo run --locked -p fortino-mock -- fortigate fixtures/mock/basic.yaml`.

## Thanks

Fortino stands on the shoulders of the open-source clients that made FortiGate SSL VPNs usable without the vendor client. Thank you to:

- **[openfortivpn](https://github.com/adrienverge/openfortivpn)** (Adrien Vergé and contributors). Its clear implementation of the SSL VPN login and PPP tunnel was our reference for early debugging, and its pinned build proved the PPP path on a real gateway (milestone 1).
- **[OpenConnect](https://www.infradead.org/openconnect/fortinet.html)** (David Woodhouse, Daniel Lenski and contributors), whose Fortinet support documents the protocol, PPP-over-DTLS and the challenge forms.
- The projects around them: **[openfortivpn-webview](https://github.com/gm-vm/openfortivpn-webview)** for SAML login, **[NetworkManager-fortisslvpn](https://gitlab.gnome.org/GNOME/NetworkManager-fortisslvpn)** for Linux desktop integration, and GUIs such as **OpenFortiGUI**, **[OpenFortiVPN GUI](https://e1z0.net/software/openfortivpn-gui)** and **[fcovpn](https://github.com/jiriteach/fcovpn)**.

## How Fortino compares

Fortino is still in development: the table shows **target** behaviour for Fortino, and its status column says what works today. Entries for the other clients come from their documentation (November 2026); corrections are welcome.

| | Fortino (status) | openfortivpn | OpenConnect `--protocol=fortinet` | FortiClient VPN (vendor) |
| --- | --- | --- | --- | --- |
| License | GPL-3.0-or-later | GPL-3.0 + OpenSSL exception | LGPL-2.1 | Proprietary |
| Language | Rust daemon, Swift app | C | C | — |
| Password + token code | Yes (password live on one gateway; codes tested against the mock) | Yes | Yes (tokeninfo and HTML forms) | Yes |
| FortiToken Mobile push | Planned | Yes | Not documented | Yes |
| SAML | Planned | Yes (`--saml-login`, or openfortivpn-webview) | Not documented | Yes |
| Client certificate | Planned | Yes | Yes | Yes |
| PPP tunnel | Working on one live gateway (in-process, no pppd); not yet in a release | Yes (pppd) | Yes (built-in PPP) | Yes |
| Raw-IP "tun" tunnel (FortiOS ≥ 5.6.6 v2 protocol) | Planned | No | No | Yes |
| DTLS | Planned | No | Yes (preferred, TLS fallback) | Yes |
| EMS registration (needed by some gateways) | In development: agent works against the mock EMS; truthful posture only | No | No | Yes |
| **Switching gateways switches EMS** (one registration per EMS, chosen by the VPN profile) | **By design; registration store and agent in place, daemon wiring next** | No EMS | No EMS | No: one EMS per machine; changing to a gateway with another EMS means re-registering |
| FortiClient request headers (`FSV_*`, User-Agent) | In development, default | No | No | Yes |
| Per-domain split DNS | Yes (macOS controller, not yet live-tested) | Limited (two servers, one suffix) | Via vpnc-script | Yes |
| IPv6 block during IPv4 tunnels | Yes (pf anchor, not yet live-tested) | No | Via script | Yes |
| Network rollback after crash | Yes (write-ahead journal) | Partial | Script-dependent | Yes |
| macOS app | Native SwiftUI menu bar | Third-party GUIs | OpenConnect-GUI | Yes |
| Headless CLI | Yes (`fortino`) | Yes | Yes | Limited |
| Security suite (AV, web filter, ZTNA…) | No (out of scope) | No | No | Paid editions |

Why another client: some gateways admit a tunnel only for clients registered with the organization's FortiClient EMS, and no open-source client implements EMS. Fortino will register and report its real state; it never fakes compliance. Ask your IT or security team before registering it with a corporate EMS.

Other related projects: [openfortivpn-go](https://pkg.go.dev/github.com/elizandrodantas/openfortivpn-go) (a Go port) and LivConnect (a multi-protocol desktop wrapper around openfortivpn and OpenConnect).

Project code is licensed under [GPL-3.0-or-later](LICENSE).
