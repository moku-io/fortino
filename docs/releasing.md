# Building and releasing

## Build the downloads

After changing the source, rebuild everything (Rust binaries, app bundle and DMG) with one command. The VPN service ships inside `Fortino.app`, and macOS only registers it from a Developer ID-signed app, so sign the build:

```sh
SIGN_APP="Developer ID Application: …" scripts/package-macos.sh   # → target/package/Fortino-<version>.dmg
scripts/macos-vm-dmg-test.sh   # optional: install it from the DMG in a disposable VM and test it
```

`security find-identity -v -p codesigning` prints the exact identity name for `SIGN_APP`. The first build asks to let the terminal control Finder (it lays out the DMG window); allow it in System Settings → Privacy & Security → Automation.

Users drag Fortino from the DMG to Applications, open it and allow its VPN service once in System Settings → General → Login Items; moving it to the Trash uninstalls it. The version comes from `CFBundleShortVersionString` in `apps/macos/Resources/Info.plist`; raise it (and `CFBundleVersion`) for each build you hand out. Profiles survive reinstalling. For what the bundle contains, configuration and notarization, see [DEVELOPMENT.md](../DEVELOPMENT.md#installer).

## Release checklist

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
