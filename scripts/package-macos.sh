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
ART="$ROOT/apps/macos/.build/art"
VOL="Fortino"
ln -s /Applications "$OUT/dmg/Applications"
mkdir "$OUT/dmg/.background"
tiffutil -cathidpicheck "$ART/bg.png" "$ART/bg@2x.png" -out "$OUT/dmg/.background/background.tiff" 2>/dev/null

# A writable image first, so Finder can store the window layout, then compress it.
RW="$OUT/rw.dmg"
hdiutil create -quiet -volname "$VOL" -srcfolder "$OUT/dmg" -fs HFS+ -format UDRW -size 200m "$RW"
for v in "/Volumes/$VOL"*; do [[ -d "$v" ]] && hdiutil detach -quiet "$v" -force; done
MNT=$(hdiutil attach -nobrowse -noverify -noautoopen "$RW" | awk -F'\t' '/\/Volumes\// {print $NF}')
# Window 640 x 400 (plus the title bar), no toolbar or sidebar, 128 px icons, centres as drawn
# in make-art.swift. Finder asks once for permission to be controlled by the terminal.
if ! osascript <<EOT
tell application "Finder"
    tell disk "$(basename "$MNT")"
        open
        set current view of container window to icon view
        set toolbar visible of container window to false
        set statusbar visible of container window to false
        set the bounds of container window to {200, 120, 840, 548}
        set opts to the icon view options of container window
        set arrangement of opts to not arranged
        set icon size of opts to 128
        set text size of opts to 13
        set background picture of opts to file ".background:background.tiff"
        set position of item "Fortino.app" of container window to {170, 190}
        set position of item "Applications" of container window to {470, 190}
        update without registering applications
        delay 1
        close
    end tell
end tell
EOT
then
    echo "warning: Finder layout not applied (allow the terminal to control Finder in Privacy & Security > Automation)" >&2
fi
chflags hidden "$MNT/.background" 2>/dev/null || true
# The disk's own icon (after Finder's pass, which can drop it).
cp "$APP/Contents/Resources/AppIcon.icns" "$MNT/.VolumeIcon.icns"
SetFile -a V "$MNT/.VolumeIcon.icns"
SetFile -a C "$MNT"
sync
hdiutil detach -quiet "$MNT"
hdiutil convert -quiet "$RW" -format UDZO -imagekey zlib-level=9 -o "$DMG"
rm -f "$RW"
[[ -n "${SIGN_APP:-}" ]] && codesign --force --timestamp --sign "$SIGN_APP" "$DMG"

if [[ -n "${NOTARY_PROFILE:-}" ]]; then
    [[ -n "${SIGN_APP:-}" ]] || { echo "notarizing needs SIGN_APP"; exit 2; }
    echo "==> Notarizing"
    xcrun notarytool submit "$DMG" --keychain-profile "$NOTARY_PROFILE" --wait
    xcrun stapler staple "$DMG"
fi

rm -rf "$OUT/dmg"
shasum -a 256 "$DMG"
