# Contributing

Thanks for helping. Before opening a pull request, read [AGENTS.md](AGENTS.md): the independent, secrets and root rules apply to people too.

## Licensing of contributions

Fortino is distributed under [GPL-3.0-or-later](LICENSE). Contributions are accepted on an *inbound MIT* basis:

By submitting a contribution, you license it to the project and its maintainers under the [MIT License](https://opensource.org/license/mit), in addition to its distribution under GPL-3.0-or-later as part of Fortino. This keeps the option to relicense the project in the future without having to track down every contributor.

Sign off each commit (`git commit -s`) to confirm that you wrote the change or have the right to submit it under these terms ([Developer Certificate of Origin](https://developercertificate.org/)).

## Checks

Before submitting: `cargo fmt --all`, `cargo clippy --workspace --all-targets` with no warnings, `cargo test --workspace`, and `swift build --package-path apps/macos` for app changes.
