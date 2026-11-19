#!/bin/sh
# Builds OpenFortiClient.app (unsigned) with ofctl inside, for development.
# Usage: apps/macos/scripts/bundle.sh [debug|release]   (run from anywhere)
set -eu
config="${1:-debug}"
here="$(cd "$(dirname "$0")/.." && pwd)"
root="$(cd "$here/../.." && pwd)"

if [ "$config" = release ]; then cargo_flag="--release"; else cargo_flag=""; fi
(cd "$root" && cargo build --locked -p ofc-cli $cargo_flag)
(cd "$here" && swift build -c "$config" --product OpenFortiClient)

app="$here/.build/OpenFortiClient.app"
rm -rf "$app"
mkdir -p "$app/Contents/MacOS"
cp "$here/Resources/Info.plist" "$app/Contents/Info.plist"
cp "$here/.build/$config/OpenFortiClient" "$app/Contents/MacOS/OpenFortiClient"
cp "$root/target/$config/ofctl" "$app/Contents/MacOS/ofctl"
echo "$app"
