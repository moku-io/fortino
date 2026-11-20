#!/bin/bash
# Builds the Fortino installer: target/package/Fortino-<version>.pkg
#
# Installs Fortino.app, the fortinod launchd service, the tunnel worker, the fortino CLI and an
# uninstaller. Unsigned by default (Gatekeeper then asks for "Open Anyway" in Privacy & Security,
# or remove the quarantine with xattr). To sign and notarize, set:
#
#   SIGN_APP="Developer ID Application: NAME (TEAMID)"   signs binaries and app (hardened runtime)
#   SIGN_PKG="Developer ID Installer: NAME (TEAMID)"     signs the .pkg
#   NOTARY_PROFILE=fortino                                notarizes and staples the .pkg
#                                                         (xcrun notarytool store-credentials fortino ...)
#
# Builds for this Mac's architecture only.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PKGSRC="$ROOT/packaging/macos"
OUT="$ROOT/target/package"
STAGE="$OUT/root"
VERSION=$(/usr/libexec/PlistBuddy -c 'Print CFBundleShortVersionString' "$ROOT/apps/macos/Resources/Info.plist")
ARCH=$(uname -m)

echo "==> Building Fortino $VERSION ($ARCH)"
(cd "$ROOT" && cargo build --locked --release -p fortinod -p fortino-cli -p fortino-sslvpn \
    --bin fortinod --bin fortino --bin fortino-sslvpn-worker)
APP=$("$ROOT/apps/macos/scripts/bundle.sh" release | tail -1)

echo "==> Staging"
rm -rf "$OUT"
mkdir -p "$STAGE/Applications" "$STAGE/usr/local/bin" "$STAGE/usr/local/libexec/fortino" \
    "$STAGE/Library/LaunchDaemons"
cp -R "$APP" "$STAGE/Applications/Fortino.app"
install -m 0755 "$ROOT/target/release/fortinod" "$ROOT/target/release/fortino-sslvpn-worker" \
    "$PKGSRC/uninstall.sh" "$STAGE/usr/local/libexec/fortino/"
install -m 0755 "$ROOT/target/release/fortino" "$STAGE/usr/local/bin/fortino"
install -m 0644 "$PKGSRC/org.fortino.fortinod.plist" "$STAGE/Library/LaunchDaemons/"

if [[ -n "${SIGN_APP:-}" ]]; then
    echo "==> Signing with $SIGN_APP"
    sign() { codesign --force --timestamp --options runtime --sign "$SIGN_APP" "$@"; }
    sign --identifier org.fortino.fortinod "$STAGE/usr/local/libexec/fortino/fortinod"
    sign --identifier org.fortino.worker "$STAGE/usr/local/libexec/fortino/fortino-sslvpn-worker"
    sign --identifier org.fortino.cli "$STAGE/usr/local/bin/fortino"
    sign --identifier org.fortino.cli "$STAGE/Applications/Fortino.app/Contents/Helpers/fortino"
    sign "$STAGE/Applications/Fortino.app"
    codesign --verify --strict --deep "$STAGE/Applications/Fortino.app"
fi

echo "==> Building the package"
# No extended attributes in the payload (they become ._ files).
xattr -cr "$STAGE"
export COPYFILE_DISABLE=1
# Install the app where the package says, even if a copy exists elsewhere.
COMPONENTS="$OUT/components.plist"
pkgbuild --analyze --root "$STAGE" "$COMPONENTS" >/dev/null
/usr/libexec/PlistBuddy -c 'Set :0:BundleIsRelocatable false' "$COMPONENTS"
pkgbuild --root "$STAGE" --component-plist "$COMPONENTS" --scripts "$PKGSRC/scripts" \
    --identifier org.fortino.pkg --version "$VERSION" --install-location / \
    "$OUT/fortino-component.pkg"

sed -e "s/@VERSION@/$VERSION/" -e "s/@ARCHS@/$ARCH/" "$PKGSRC/distribution.xml" > "$OUT/distribution.xml"
PKG="$OUT/Fortino-$VERSION.pkg"
sign_pkg=()
[[ -n "${SIGN_PKG:-}" ]] && sign_pkg=(--sign "$SIGN_PKG" --timestamp)
productbuild --distribution "$OUT/distribution.xml" --resources "$PKGSRC/resources" \
    --package-path "$OUT" "${sign_pkg[@]+"${sign_pkg[@]}"}" "$PKG"

if [[ -n "${NOTARY_PROFILE:-}" ]]; then
    [[ -n "${SIGN_APP:-}" && -n "${SIGN_PKG:-}" ]] || { echo "notarizing needs SIGN_APP and SIGN_PKG"; exit 2; }
    echo "==> Notarizing"
    xcrun notarytool submit "$PKG" --keychain-profile "$NOTARY_PROFILE" --wait
    xcrun stapler staple "$PKG"
fi

rm -rf "$STAGE" "$OUT/fortino-component.pkg" "$COMPONENTS" "$OUT/distribution.xml"
shasum -a 256 "$PKG"
echo "$PKG"
