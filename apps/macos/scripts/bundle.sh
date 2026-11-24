#!/bin/sh
# Builds Fortino.app: the menu-bar app, the fortinod VPN service (registered by the app with
# SMAppService, also the tunnel worker as `fortinod --worker`) and the fortino CLI.
# Usage: apps/macos/scripts/bundle.sh [debug|release]   (run from anywhere)
#
#   Contents/MacOS/Fortino                               app
#   Contents/MacOS/fortinod                              root service and tunnel worker
#   Contents/Helpers/fortino                             CLI
#   Contents/Frameworks/Sparkle.framework                app updates
#   Contents/Library/LaunchDaemons/org.fortino.fortinod.plist
#
# Builds for this Mac's architecture. FORTINO_UNIVERSAL=1 builds arm64 and x86_64 and joins them
# with lipo (needs rustup with the aarch64-apple-darwin and x86_64-apple-darwin targets).
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
# Separate folders: the default macOS file system ignores case, so the app (Fortino) and the CLI
# (fortino) can't share one.
bins="$here/.build/bundle-bin"
rm -rf "$bins"
mkdir -p "$bins/rust" "$bins/app"
cargo_build() {
    (cd "$root" && cargo build --locked -p fortino-cli -p fortinod --bin fortino --bin fortinod $cargo_flag "$@")
}
if [ -n "${FORTINO_UNIVERSAL:-}" ]; then
    for t in aarch64-apple-darwin x86_64-apple-darwin; do
        if ! (cd "$root" && rustup target list --installed 2>/dev/null) | grep -qx "$t"; then
            echo "error: universal builds need rustup and its $t target (rustup target add $t)" >&2
            exit 2
        fi
        cargo_build --target "$t"
    done
    for b in fortino fortinod; do
        lipo -create -output "$bins/rust/$b" \
            "$root/target/aarch64-apple-darwin/$config/$b" "$root/target/x86_64-apple-darwin/$config/$b"
    done
    # One build per architecture: works with the Command Line Tools, unlike several --arch.
    apps=""
    for t in arm64-apple-macosx13.0 x86_64-apple-macosx13.0; do
        (cd "$here" && swift build -c "$config" --product Fortino --triple "$t")
        apps="$apps $(cd "$here" && swift build -c "$config" --triple "$t" --show-bin-path)/Fortino"
    done
    # shellcheck disable=SC2086
    lipo -create -output "$bins/app/Fortino" $apps
else
    cargo_build
    cp "$root/target/$config/fortino" "$root/target/$config/fortinod" "$bins/rust/"
    (cd "$here" && swift build -c "$config" --product Fortino)
    cp "$(cd "$here" && swift build -c "$config" --show-bin-path)/Fortino" "$bins/app/"
fi

app="$here/.build/Fortino.app"
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Helpers" "$app/Contents/Library/LaunchDaemons" \
    "$app/Contents/Resources" "$app/Contents/Frameworks"
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
cp "$bins/app/Fortino" "$bins/rust/fortinod" "$app/Contents/MacOS/"
cp "$bins/rust/fortino" "$app/Contents/Helpers/fortino"
# Sparkle (arm64 + x86_64). Its XPC services are only needed by sandboxed apps; Fortino is not
# sandboxed, so they are left out. Its MIT licence travels with it.
sparkle="$here/.build/artifacts/sparkle/Sparkle"
ditto "$sparkle/Sparkle.xcframework/macos-arm64_x86_64/Sparkle.framework" \
    "$app/Contents/Frameworks/Sparkle.framework"
rm -rf "$app/Contents/Frameworks/Sparkle.framework/XPCServices" \
    "$app/Contents/Frameworks/Sparkle.framework/Versions/B/XPCServices"
cp "$sparkle/LICENSE" "$app/Contents/Resources/Sparkle-LICENSE.txt"
# Removing the XPC services breaks the framework's ad-hoc seal; re-seal it ad hoc so unsigned
# bundles still load it. package-macos.sh signs it again with the Developer ID.
codesign --force --sign - "$app/Contents/Frameworks/Sparkle.framework/Versions/B/Updater.app" \
    "$app/Contents/Frameworks/Sparkle.framework/Versions/B/Autoupdate" >&2
codesign --force --sign - "$app/Contents/Frameworks/Sparkle.framework" >&2
echo "$app"
