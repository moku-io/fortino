#!/bin/bash
# Builds the Fortino download: target/package/Fortino-<version>.dmg (drag Fortino to
# Applications).
#
# Fortino.app contains the VPN service (fortinod, also the tunnel worker), which the app
# registers with SMAppService on first launch; the user approves it once in System Settings >
# General > Login Items. Moving the app to the Trash removes it.
#
# macOS only registers the service from a Developer ID-signed app, so set at least SIGN_APP:
#
#   SIGN_APP="Developer ID Application: NAME (TEAMID)"   signs the binaries, app and DMG
#   NOTARY_PROFILE=fortino                                notarizes and staples the DMG
#                                                         (xcrun notarytool store-credentials fortino ...)
#
# Unsigned builds are for checking the bundle only. Builds for this Mac's architecture only.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/target/package"
VERSION=$(/usr/libexec/PlistBuddy -c 'Print CFBundleShortVersionString' "$ROOT/apps/macos/Resources/Info.plist")
ARCH=$(uname -m)
export COPYFILE_DISABLE=1

echo "==> Building Fortino $VERSION ($ARCH)"
# The daemon verifies the copy it runs as the worker against this team (see procworker.rs).
if [[ "${SIGN_APP:-}" =~ \(([A-Z0-9]{10})\)$ ]]; then
    export FORTINO_TEAM_ID="${BASH_REMATCH[1]}"
else
    unset FORTINO_TEAM_ID
fi
BUILT=$("$ROOT/apps/macos/scripts/bundle.sh" release | tail -1)
rm -rf "$OUT"
mkdir -p "$OUT/dmg"
APP="$OUT/dmg/Fortino.app"
cp -R "$BUILT" "$APP"
xattr -cr "$APP"

if [[ -n "${SIGN_APP:-}" ]]; then
    echo "==> Signing with $SIGN_APP"
    sign() { codesign --force --timestamp --options runtime --sign "$SIGN_APP" "$@"; }
    sign --identifier org.fortino.fortinod "$APP/Contents/MacOS/fortinod"
    sign --identifier org.fortino.cli "$APP/Contents/Helpers/fortino"
    sign "$APP"
    codesign --verify --strict --deep "$APP"
else
    echo "==> UNSIGNED: the app runs, but macOS will not register its VPN service"
fi

echo "==> Building the disk image"
DMG="$OUT/Fortino-$VERSION.dmg"
ln -s /Applications "$OUT/dmg/Applications"
hdiutil create -quiet -volname "Fortino $VERSION" -srcfolder "$OUT/dmg" -fs HFS+ -format UDZO "$DMG"
[[ -n "${SIGN_APP:-}" ]] && codesign --force --timestamp --sign "$SIGN_APP" "$DMG"

if [[ -n "${NOTARY_PROFILE:-}" ]]; then
    [[ -n "${SIGN_APP:-}" ]] || { echo "notarizing needs SIGN_APP"; exit 2; }
    echo "==> Notarizing"
    xcrun notarytool submit "$DMG" --keychain-profile "$NOTARY_PROFILE" --wait
    xcrun stapler staple "$DMG"
fi

rm -rf "$OUT/dmg"
shasum -a 256 "$DMG"
