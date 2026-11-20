#!/bin/sh
# Builds Fortino.app: the menu-bar app, the fortinod VPN service (registered by the app with
# SMAppService, also the tunnel worker as `fortinod --worker`) and the fortino CLI.
# Usage: apps/macos/scripts/bundle.sh [debug|release]   (run from anywhere)
#
#   Contents/MacOS/Fortino                               app
#   Contents/MacOS/fortinod                              root service and tunnel worker
#   Contents/Helpers/fortino                             CLI
#   Contents/Library/LaunchDaemons/org.fortino.fortinod.plist
#
# Unsigned bundles run the app, but macOS only registers the service from a bundle signed with
# a Developer ID (scripts/package-macos.sh signs it).
set -eu
config="${1:-debug}"
here="$(cd "$(dirname "$0")/.." && pwd)"
root="$(cd "$here/../.." && pwd)"

if [ "$config" = release ]; then cargo_flag="--release"; else cargo_flag=""; fi
(cd "$root" && cargo build --locked -p fortino-cli -p fortinod --bin fortino --bin fortinod $cargo_flag)
(cd "$here" && swift build -c "$config" --product Fortino)

app="$here/.build/Fortino.app"
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Helpers" "$app/Contents/Library/LaunchDaemons" \
    "$app/Contents/Resources"
# App icon and disk-image background, drawn by make-art.swift (no binary assets in git).
art="$here/.build/art"
swift "$here/scripts/make-art.swift" "$art" >&2
iconutil -c icns "$art/AppIcon.iconset" -o "$app/Contents/Resources/AppIcon.icns"
cp "$here/Resources/Info.plist" "$app/Contents/Info.plist"
cp "$here/Resources/org.fortino.fortinod.plist" "$app/Contents/Library/LaunchDaemons/"
cp "$here/.build/$config/Fortino" "$app/Contents/MacOS/Fortino"
cp "$root/target/$config/fortinod" "$app/Contents/MacOS/fortinod"
cp "$root/target/$config/fortino" "$app/Contents/Helpers/fortino"
echo "$app"
