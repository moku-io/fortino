#!/bin/bash
# Builds the Fortino downloads in target/package:
#
#   Fortino-<version>.dmg   drag Fortino to Applications (the usual way to install)
#   Fortino-<version>.pkg   installs the same app and the CLI link; for scripted or managed
#                           installs, and it removes the pre-0.2 layout (/usr/local/libexec)
#
# Fortino.app contains the VPN service (fortinod, also the tunnel worker), which the app
# registers with SMAppService on first launch; the user approves it once in System Settings >
# General > Login Items. Moving the app to the Trash removes it.
#
# macOS only registers the service from a Developer ID-signed app, so set at least SIGN_APP:
#
#   SIGN_APP="Developer ID Application: NAME (TEAMID)"   signs the binaries, app and DMG
#   SIGN_PKG="Developer ID Installer: NAME (TEAMID)"     signs the .pkg
#   NOTARY_PROFILE=fortino                                notarizes and staples both
#                                                         (xcrun notarytool store-credentials fortino ...)
#
# Unsigned builds are for checking the bundle only. Builds for this Mac's architecture only.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PKGSRC="$ROOT/packaging/macos"
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
mkdir -p "$OUT/root/Applications"
APP="$OUT/root/Applications/Fortino.app"
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
mkdir -p "$OUT/dmg"
cp -R "$APP" "$OUT/dmg/"
ln -s /Applications "$OUT/dmg/Applications"
hdiutil create -quiet -volname "Fortino $VERSION" -srcfolder "$OUT/dmg" -fs HFS+ -format UDZO "$DMG"
[[ -n "${SIGN_APP:-}" ]] && codesign --force --timestamp --sign "$SIGN_APP" "$DMG"

echo "==> Building the package"
COMPONENTS="$OUT/components.plist"
pkgbuild --analyze --root "$OUT/root" "$COMPONENTS" >/dev/null
# Install to /Applications even if a copy of the app exists elsewhere.
/usr/libexec/PlistBuddy -c 'Set :0:BundleIsRelocatable false' "$COMPONENTS"
pkgbuild --quiet --root "$OUT/root" --component-plist "$COMPONENTS" --scripts "$PKGSRC/scripts" \
    --identifier org.fortino.pkg --version "$VERSION" --install-location / \
    "$OUT/fortino-component.pkg"
sed -e "s/@VERSION@/$VERSION/" -e "s/@ARCHS@/$ARCH/" "$PKGSRC/distribution.xml" > "$OUT/distribution.xml"
PKG="$OUT/Fortino-$VERSION.pkg"
sign_pkg=()
[[ -n "${SIGN_PKG:-}" ]] && sign_pkg=(--sign "$SIGN_PKG" --timestamp)
productbuild --quiet --distribution "$OUT/distribution.xml" --resources "$PKGSRC/resources" \
    --package-path "$OUT" "${sign_pkg[@]+"${sign_pkg[@]}"}" "$PKG"

if [[ -n "${NOTARY_PROFILE:-}" ]]; then
    [[ -n "${SIGN_APP:-}" && -n "${SIGN_PKG:-}" ]] || { echo "notarizing needs SIGN_APP and SIGN_PKG"; exit 2; }
    for f in "$DMG" "$PKG"; do
        echo "==> Notarizing $(basename "$f")"
        xcrun notarytool submit "$f" --keychain-profile "$NOTARY_PROFILE" --wait
        xcrun stapler staple "$f"
    done
fi

rm -rf "$OUT/root" "$OUT/dmg" "$OUT/fortino-component.pkg" "$COMPONENTS" "$OUT/distribution.xml"
shasum -a 256 "$DMG" "$PKG"
