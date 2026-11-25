# Development

How to run the daemon, CLI and desktop app on one Mac without root and without creating a real tunnel, how to test, and how to build the installer.

## Layout

| Path | Contents |
| --- | --- |
| `crates/fortino-proto-sslvpn` | Sans-IO FortiGate SSL VPN codecs: HTTP framing, login forms, tunnel settings, `0x5050` frames, PPP. |
| `crates/fortino-proto-ems` | Sans-IO FortiClient EMS codecs: requests, replies, `SYSINFO`, host-verification rules, tags. |
| `crates/fortino-sslvpn` | The native tunnel worker and `fortino-sslvpn-probe`. |
| `crates/fortino-ems` | The EMS agent, its per-server registration store and `fortino-ems-probe`. |
| `crates/fortino-config` | Profile model and validation, the SQLite profile store and the FortiClient XML importer and exporter. |
| `crates/fortino-core` | Control protocol types, framing, error and exit codes, the worker interface and the fake worker. |
| `crates/fortino-platform` | Network changes behind `NetPlatform`, with a write-ahead journal; the macOS controller. |
| `crates/fortinod` | Daemon: socket server, peer authorization, session state machine, network controller. |
| `crates/fortino-cli` | `fortino`. |
| `crates/fortino-mock` | Synthetic FortiGate and EMS servers for tests. |
| `apps/macos` | SwiftUI/AppKit menu-bar app (`Fortino`) and its protocol kit (`FortinoKit`). Updates through Sparkle, a Swift package dependency. |
| `fixtures/` | Synthetic configurations and scenarios. |

## Development daemon

The `[fake]` section of the development configuration selects the fake worker and an in-memory fake network. Nothing on the host changes.

```sh
mkdir -p target/dev
sed "s/allowed_uids = \[501\]/allowed_uids = [$(id -u)]/" fixtures/dev/fortinod-fake.toml > target/dev/fortinod.toml
cargo run -p fortinod -- --config target/dev/fortinod.toml
```

The fake gateway accepts the password `hunter2` and the code `123456`. Other `[fake]` keys script failures (`fail = "trust" | "transport" | "unsupported-policy" | "drop-after-up"`), the assigned address, routes and DNS; see `FakeWorkerConfig` in `crates/fortino-core/src/worker.rs`.

To exercise the process boundary, replace `[fake]` with a `[worker]` section that points at the stub, and add `fake_network = true`:

```toml
fake_network = true
[worker]
path = "target/debug/fortino-stub-worker"
ca_dir = "target/dev"
allow_unowned = true   # development only; production requires a root-owned executable
```

Unix socket paths are limited to about 100 bytes, so keep `socket_path` short.

## CLI

```sh
export FORTINO_SOCKET=$PWD/target/dev/fortinod.sock
fortino profile add demo-vpn --host vpn.example.org --port 10443 --realm staff --ems-server ems.example.org:9016
fortino profile list
fortino profile edit demo-vpn --dns local                 # keep this Mac's DNS while connected (default: gateway)
fortino connect demo-vpn                                  # prompts on the terminal
fortino connect demo-vpn --password-fd 3 --otp-fd 4 3<pw 4<otp   # headless
fortino profile edit demo-vpn --save-password             # save the password after the next connection
fortino password save demo-vpn                            # or save it now (prompts; --stdin reads a line)
fortino password status demo-vpn                          # saved or not, for which account; never the password
fortino password forget demo-vpn                          # remove it; --no-save-password also stops saving
fortino status --watch --json
fortino disconnect
fortino profile import export.xml --dry-run
fortino profile export -o profiles.xml                    # FortiClient XML; all profiles, or name some
fortino log-level debug                               # or error, warn, info, trace; no argument shows it
fortino ems-status ems.example.org:8013                  # registration state and the next step
fortino ems-register ems.example.org:8013                # register now (server must be approved)
```

`fortinod` starts at `RUST_LOG` (default `info`); `fortino log-level` and the app's **Log level** setting change it at runtime until the daemon restarts. At every level, logs go through a redacting writer and never carry passwords, codes or cookie values. The installed service logs to `/var/log/fortinod.log`.

Saved passwords live in the user's login Keychain, written and read only by `fortino` (the app runs its bundled copy), never by the daemon: one item per profile, service `org.fortino.vpn.<profile ID>`, account the username. A password typed during a connection is saved once the tunnel is up; a saved password the gateway rejects is marked in the item's comment and not sent again until a new one is saved. `--password-fd` bypasses the store. `FORTINO_CREDENTIAL_STORE=none` turns saved passwords off for one run.

Exit codes: 0 success, 2 invalid input or profile, 3 busy or stale revision, 4 authentication or required input, 5 trust failure, 6 network/backend failure, 7 service unavailable or permission denied, 8 unsupported policy, 9 cancellation. With `--json`, errors are printed as `{"v":1,"error":{"code":…}}`.

## Desktop app

The app needs Swift 5.9+ and macOS 13+. The Command Line Tools are enough; Xcode is optional.

```sh
FORTINO_SOCKET=$PWD/target/dev/fortinod.sock FORTINO_CLI=$PWD/target/debug/fortino \
  swift run --package-path apps/macos Fortino
apps/macos/scripts/bundle.sh            # unsigned Fortino.app, fortino CLI in Contents/Helpers
swift run --package-path apps/macos FortinoKitSelfTest
```

The app parses XML imports by running `fortino --json profile import … --dry-run` in the user's own process, so there is a single importer. `FORTINO_DEBUG_OPEN=profiles,menu-preview,import,ems-setup` opens those windows at launch. `FORTINO_DEBUG_SERVICE_UPDATE=after-disconnect` shows the service-update notice without a second build, for layout checks.

## Tests

`cargo test --workspace` runs everything unprivileged: the daemon over its socket, a real worker process (`fortino-stub-worker`), the CLI against an in-process daemon, property tests for every protocol parser, and the native worker against the mock FortiGate and EMS with an in-memory tun device.

Tests never touch your keychain: the CLI tests set `FORTINO_CREDENTIAL_STORE=file:<path>`, a plain JSON store that only debug builds accept. The Keychain backend has one round-trip test that writes a throwaway item to your login keychain and removes it; run it on request with `cargo test -p fortino-secret --features platform-store -- --ignored keychain`.

Before sending a change: `cargo fmt --all`, `cargo clippy --workspace --all-targets` with no warnings, `cargo test --workspace`, and `swift build --package-path apps/macos` for app changes.

### Root tests in a disposable macOS VM

The macOS network controller changes routes, resolvers and pf, so its live tests (`crates/fortino-platform/tests/macos_root.rs`) run only as root inside a VM with `FORTINO_VM_ROOT_TESTS=1`; anywhere else they do nothing. `scripts/macos-vm-test.sh` clones a [Tart](https://tart.run) VM (base `ghcr.io/cirruslabs/macos-sequoia-xcode:26.6`, override with `FORTINO_VM_BASE`; `TART_HOME` sets where VMs live), runs them as root and deletes the clone. Never run these tests, or anything else that changes network state as root, on your own Mac.

`scripts/macos-vm-e2e.sh` runs the whole stack in a fresh clone: the mock gateway on the VM's address, `fortinod` as root with the macOS controller, a real `utun`, and `fortino connect`. It checks split routes and DNS, the IPv6 block and a ping through the tunnel, disconnects, and compares routes, resolver keys and pf with the state before.

### Against a real gateway

`fortino-sslvpn-probe` runs the native worker in-process with an in-memory tun device, so it needs no root and changes nothing on the host. It reads a credentials file kept outside the repository (`gateway`, `username`, `password`, optional `otp`, `pin` and a test URL inside the VPN) and never prints secrets. `fortino-sslvpn-probe CREDS --info` sends only the unauthenticated `/remote/info` request. Only use gateways and EMS servers you are authorised to test; registering with an EMS creates a device record.

## Installer

```sh
scripts/package-macos.sh        # target/package/Fortino-<version>.dmg, unsigned, universal
SIGN_APP="Developer ID Application: …" \
  scripts/package-macos.sh      # signed: needed for the service to register
NOTARY_PROFILE=fortino …        # add to also notarize and staple the app and the DMG
FORTINO_UNIVERSAL=0 …           # this Mac's architecture only
scripts/macos-vm-dmg-test.sh    # install from the DMG in a disposable VM and test
scripts/release-macos.sh        # publish a release on GitHub; see docs/releasing.md
```

Universal builds need rustup with the `aarch64-apple-darwin` and `x86_64-apple-darwin` targets.

The release version is `CFBundleShortVersionString` in `apps/macos/Resources/Info.plist` (which names the DMG) and `version` under `[workspace.package]` in `Cargo.toml` (which `fortino -V` reports); bump both together, and `cargo test` fails if they differ.

`Fortino.app` carries everything (built by `apps/macos/scripts/bundle.sh`):

| Path in the bundle | Role |
| --- | --- |
| `Contents/MacOS/Fortino` | Menu-bar app, runs as the user |
| `Contents/MacOS/fortinod` | Root VPN service, and the tunnel worker as `fortinod --worker` |
| `Contents/Helpers/fortino` | CLI |
| `Contents/Frameworks/Sparkle.framework` | App updates (without its XPC services, which only sandboxed apps need) |
| `Contents/Library/LaunchDaemons/org.fortino.fortinod.plist` | launchd job, log `/var/log/fortinod.log` |

**Install.** Drag the app to Applications and open it. It registers the service with `SMAppService`; the user approves it once in System Settings → General → Login Items. Settings → Command Line links `/usr/local/bin/fortino` to the bundle. macOS registers the service only from a Developer ID-signed bundle.

**Update.** The app checks the feed in `SUFeedURL` (the `appcast.xml` of the latest GitHub release) once a day and on **Check for Updates…**. Sparkle accepts the feed and the DMG only when they are signed with the EdDSA key whose public half is `SUPublicEDKey`, shows the release notes with **Install Update**, **Remind Me Later** and **Skip This Version**, replaces the app and relaunches it. When a scheduled check finds an update while no Fortino window is in front, the menu-bar panel shows **Update to Fortino …** instead of opening a window. Dragging a new app over the old one works too. Either way, the new app compares its build ID with the running service's and asks an older service to restart, right away when disconnected or after the next disconnect, so a connected VPN stays up during the update. Settings → General turns automatic checks off. `FORTINO_UPDATE_FEED` points a copy at another (still signed) feed for testing.

**Uninstall.** Move Fortino to the Trash; macOS removes the service with it. Profiles and settings stay in `/Library/Application Support/Fortino`.

**Configuration.** The daemon needs no file: by default every local user (group `staff`) may connect, the daemon is its own worker, and gateways are checked against `/etc/ssl/cert.pem` unless an administrator provisions `/Library/Application Support/Fortino/ca/<trust-id>.pem` (a PEM CA bundle or `sha256:<hex>` pin lines). If a gateway sends its certificate without the intermediate CA certificates, the client downloads them over plain HTTP (port 80 only) from the certificate's CA Issuers URL, as macOS does. The download can be a DER, PEM or PKCS#7 `.p7c` file. Downloaded certificates only fill gaps in the chain and never act as roots, and nothing is fetched for pinned gateways. When a gateway's certificate still fails (typically a gateway reached by an IP address its certificate doesn't name), the app offers **Review Certificate…**. After a warning showing the subject and SHA-256, and the administrator's password, it writes `sha256:<hex>` to a root-owned marker in `/private/var/db/fortino-gateway-pins/`, named by the SHA-256 of `host:port`. For profiles using the default `system` trust, the service then trusts exactly that leaf certificate for that gateway; a changed certificate fails again and is reviewed again. Delete the marker to undo. To change that, create `/Library/Application Support/Fortino/fortinod.toml` (same keys as the development configs) and restart the service with `sudo launchctl kickstart -k system/org.fortino.fortinod`. To restrict access, set `allowed_groups = ["fortino"]` for a group you create with `dseditgroup`.

**Why the worker is `fortinod` itself.** A dragged-in app is owned by the user, so a binary inside the bundle could be replaced while the service runs. The daemon copies its own executable at startup into `/Library/Application Support/Fortino/libexec` (root-owned) and, in signed builds, requires the copy to pass `codesign --verify` for the team baked into the build. Workers run only from that copy.

## When the Mac loses connectivity during a test

Run `scripts/net-diag.sh` on the affected Mac while the connection is stuck, before disconnecting or rebooting. It writes a private, timestamped report to your home directory with interface, routing, resolver and firewall state and connectivity probes. Review it before sharing: it contains local and VPN addresses, MAC addresses, routes and resolver domains.
