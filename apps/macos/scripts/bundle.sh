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
# One build ID for the daemon, the CLI and the app's Info.plist (FortinoBuildID). The app
# compares the daemon's with its own after an update and asks an older daemon to restart. A
# clean tree gives the commit; local changes add a timestamp so every such build differs.
if [ -z "${FORTINO_BUILD_ID:-}" ]; then
    FORTINO_BUILD_ID="$(git -C "$root" rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"
    if [ -n "$(git -C "$root" status --porcelain 2>/dev/null)" ]; then
        FORTINO_BUILD_ID="$FORTINO_BUILD_ID-dirty-$(date -u +%Y%m%dT%H%M%SZ)"
    fi
fi
export FORTINO_BUILD_ID
echo "build $FORTINO_BUILD_ID" >&2
(cd "$root" && cargo build --locked -p fortino-cli -p fortinod --bin fortino --bin fortinod $cargo_flag)
(cd "$here" && swift build -c "$config" --product Fortino)

app="$here/.build/Fortino.app"
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Helpers" "$app/Contents/Library/LaunchDaemons" \
    "$app/Contents/Resources"
# App icon from Resources/AppIcon.iconset (make-app-icon.swift); disk-image background drawn by make-art.swift.
art="$here/.build/art"
swift "$here/scripts/make-art.swift" "$art" >&2
cp "$here"/Resources/ShieldStatusBar*.png "$app/Contents/Resources/"
cp "$here/Resources/Info.plist" "$app/Contents/Info.plist"
# Layered Liquid Glass icon (Resources/AppIcon.icon, Icon Composer) when Xcode's actool is available:
# it writes Assets.car plus a pre-rendered AppIcon.icns for older systems (up to 256 px @2x). Target 26.0
# because actool 26.6 crashes rendering the legacy variants for older targets on a Sequoia host.
# Without Xcode, the flat iconset is used.
if actool=$(xcrun --find actool 2>/dev/null); then
    "$actool" "$here/Resources/AppIcon.icon" --compile "$app/Contents/Resources" \
        --app-icon AppIcon --platform macosx --minimum-deployment-target 26.0 \
        --output-partial-info-plist "$here/.build/icon-partial.plist" >/dev/null
    /usr/libexec/PlistBuddy -c "Add :CFBundleIconName string AppIcon" "$app/Contents/Info.plist"
else
    iconutil -c icns "$here/Resources/AppIcon.iconset" -o "$app/Contents/Resources/AppIcon.icns"
fi
/usr/libexec/PlistBuddy -c "Add :FortinoBuildID string $FORTINO_BUILD_ID" "$app/Contents/Info.plist"
cp "$here/Resources/org.fortino.fortinod.plist" "$app/Contents/Library/LaunchDaemons/"
cp "$here/.build/$config/Fortino" "$app/Contents/MacOS/Fortino"
cp "$root/target/$config/fortinod" "$app/Contents/MacOS/fortinod"
cp "$root/target/$config/fortino" "$app/Contents/Helpers/fortino"
echo "$app"
