# Building and releasing

Fortino is published as a signed, notarized, universal (Apple silicon and Intel) DMG on [GitHub Releases](https://github.com/moku-io/fortino/releases). Installed copies update themselves through [Sparkle](https://sparkle-project.org): they read `appcast.xml` from the latest release, check its EdDSA signature and the DMG's against the public key in the app, and offer the update with its release notes.

## Build a DMG

The VPN service ships inside `Fortino.app`, and macOS only registers it from a Developer ID-signed app, so sign the build:

```sh
SIGN_APP="Developer ID Application: …" scripts/package-macos.sh   # → target/package/Fortino-<version>.dmg
NOTARY_PROFILE=fortino …                                           # add to notarize and staple the app and the DMG
FORTINO_UNIVERSAL=0 …                                              # this Mac's architecture only (no rustup needed)
scripts/macos-vm-dmg-test.sh   # optional: install it from the DMG in a disposable VM and test it
```

`security find-identity -v -p codesigning` prints the exact identity name for `SIGN_APP`. The first build asks to let the terminal control Finder (it lays out the DMG window); allow it in System Settings → Privacy & Security → Automation.

The script signs inside out (Sparkle's helpers, Sparkle, `fortinod`, `fortino`, the app) with the hardened runtime, checks that every binary has both architectures, and with `NOTARY_PROFILE` notarizes and staples the app, then the DMG, and checks both with `stapler validate` and `spctl`.

## One-time setup for releases

1. **Rust targets.** Universal builds need [rustup](https://rustup.rs) (a Homebrew `rust` cannot cross-compile):
   ```sh
   rustup target add aarch64-apple-darwin x86_64-apple-darwin
   ```
2. **Notary credentials.** With an app-specific password from appleid.apple.com (or an App Store Connect API key, see `xcrun notarytool store-credentials --help`):
   ```sh
   xcrun notarytool store-credentials fortino --apple-id <Apple ID> --team-id <team ID>
   ```
3. **Update signing key.** Sparkle's tools come with the Swift package (`swift package resolve --package-path apps/macos`). Create the EdDSA key once; it stays in the login keychain and the command prints the public key:
   ```sh
   apps/macos/.build/artifacts/sparkle/Sparkle/bin/generate_keys --account fortino
   ```
   Put the public key in `SUPublicEDKey` in `apps/macos/Resources/Info.plist`. Back up the private key (`generate_keys --account fortino -x <file>`, then store the file somewhere safe and delete it). Installed copies only accept updates signed with this key: if it is lost, users have to download the next version by hand.
4. **GitHub.** `gh auth login` with permission to create releases. The repository must be public, since installed copies download the feed and the DMG without credentials.

## Release checklist

1. Add a `## <version>` section to [CHANGELOG.md](../CHANGELOG.md). It becomes the GitHub release notes and the text in the app's update window (Markdown).
2. Raise `CFBundleShortVersionString` and `CFBundleVersion` in `apps/macos/Resources/Info.plist`, and `version` under `[workspace.package]` in `Cargo.toml` (`cargo test` fails if they differ). Sparkle compares `CFBundleVersion`, so it must grow with every release and is never reused.
3. Check the tree:
   ```sh
   cargo fmt --all --check
   cargo clippy --workspace --all-targets
   cargo test --locked --workspace
   swift build --package-path apps/macos
   ```
4. Commit and push to `main`.
5. Build, notarize and review the feed without publishing:
   ```sh
   SIGN_APP="Developer ID Application: …" NOTARY_PROFILE=fortino scripts/release-macos.sh --dry-run
   ```
   Check `target/package/appcast.xml` and `target/package/notes.md`; optionally run `scripts/macos-vm-dmg-test.sh`.
6. Publish:
   ```sh
   SIGN_APP="Developer ID Application: …" NOTARY_PROFILE=fortino scripts/release-macos.sh
   ```
   It checks the tree, the tag, the changelog and that the build number is above the published one, builds and notarizes again, signs the DMG and the feed with the update key, tags `v<version>`, creates the release as a draft with `Fortino-<version>.dmg` and `appcast.xml`, publishes it and checks that the public feed serves the new build.

Installed copies find the update at their next daily check, or at once with **Check for Updates…**.

**A bad release.** Fix forward with a higher `CFBundleVersion`. If the release must go now, delete it or mark it as a pre-release: the feed URL follows the latest full release, so installed copies go back to seeing the previous one.

## Testing an update

`FORTINO_UPDATE_FEED` makes an installed copy read another feed, for example a signed `appcast.xml` for a test build:

```sh
FORTINO_UPDATE_FEED=https://example.org/test/appcast.xml /Applications/Fortino.app/Contents/MacOS/Fortino
```

The feed and the DMG must still be signed with the update key, so the override cannot install anything else.

The synthetic TLS gateway still runs with `cargo run --locked -p fortino-mock -- fortigate fixtures/mock/basic.yaml`.
