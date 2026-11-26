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
#   NOTARY_PROFILE=fortino                                notarizes and staples the app and the DMG
#                                                         (xcrun notarytool store-credentials fortino ...)
#
# Unsigned builds are for checking the bundle only. The DMG is universal (arm64 and x86_64), which
# needs rustup with both macOS targets; FORTINO_UNIVERSAL=0 builds for this Mac only.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/target/package"
VERSION=$(/usr/libexec/PlistBuddy -c 'Print CFBundleShortVersionString' "$ROOT/apps/macos/Resources/Info.plist")
NOTARY_PROFILE="${NOTARY_PROFILE:-}"
export COPYFILE_DISABLE=1
if [[ "${FORTINO_UNIVERSAL:-1}" == 0 ]]; then
    unset FORTINO_UNIVERSAL
    ARCHS=$(uname -m)
else
    export FORTINO_UNIVERSAL=1
    ARCHS="x86_64 arm64"
fi

echo "==> Building Fortino $VERSION ($ARCHS)"
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

for bin in MacOS/Fortino MacOS/fortinod Helpers/fortino; do
    got=$(lipo -archs "$APP/Contents/$bin")
    [[ "$got" == "$ARCHS" ]] || { echo "error: $bin is built for '$got', expected '$ARCHS'" >&2; exit 1; }
done
# Sparkle comes prebuilt and universal: it only has to include ours.
got=$(lipo -archs "$APP/Contents/Frameworks/Sparkle.framework/Versions/B/Sparkle")
for a in $ARCHS; do
    [[ " $got " == *" $a "* ]] || { echo "error: Sparkle lacks $a (has '$got')" >&2; exit 1; }
done
# Each binary is the one its name says, on every architecture (x86_64 runs under Rosetta here).
for arch in $ARCHS; do
    if ! arch "-$arch" /usr/bin/true 2>/dev/null; then
        echo "warning: cannot run $arch binaries on this Mac; not checked" >&2
        continue
    fi
    cli=$(perl -e 'alarm 20; exec @ARGV' arch "-$arch" "$APP/Contents/Helpers/fortino" --version 2>&1 || true)
    [[ "$cli" == "fortino $VERSION" ]] || { echo "error: Helpers/fortino ($arch) answered '$cli'" >&2; exit 1; }
    perl -e 'alarm 20; exec @ARGV' arch "-$arch" "$APP/Contents/MacOS/fortinod" --help >/dev/null 2>&1 \
        || { echo "error: MacOS/fortinod ($arch) does not run" >&2; exit 1; }
done

if [[ -n "$NOTARY_PROFILE" ]]; then
    [[ -n "${SIGN_APP:-}" ]] || { echo "notarizing needs SIGN_APP"; exit 2; }
fi
notarize() {
    local name report
    name=$(basename "$1")
    report="$OUT/notary-$name.json"
    echo "==> Notarizing $name"
    # Uploads to Apple sometimes time out; a failed upload leaves no submission, so try again.
    # A submission Apple processed and rejected ("Invalid") is not retried.
    for attempt in 1 2 3; do
        xcrun notarytool submit "$1" --keychain-profile "$NOTARY_PROFILE" --wait --output-format json \
            >"$report" || true
        grep -q '"status" *: *"Accepted"' "$report" && return 0
        grep -q '"status"' "$report" && break
        echo "warning: upload of $name failed (attempt $attempt of 3)" >&2
        sleep 10
    done
    echo "error: notarization of $name was not accepted; see $report" >&2
    echo "       xcrun notarytool log <id> --keychain-profile $NOTARY_PROFILE" >&2
    exit 1
}

if [[ -n "${SIGN_APP:-}" ]]; then
    echo "==> Signing with $SIGN_APP"
    sign() { codesign --force --timestamp --options runtime --sign "$SIGN_APP" "$@"; }
    # Inside out: Sparkle's helpers, Sparkle, our binaries, then the app that seals them all.
    SPARKLE="$APP/Contents/Frameworks/Sparkle.framework/Versions/B"
    sign "$SPARKLE/Autoupdate"
    sign "$SPARKLE/Updater.app"
    sign "$APP/Contents/Frameworks/Sparkle.framework"
    sign --identifier org.fortino.fortinod "$APP/Contents/MacOS/fortinod"
    sign --identifier org.fortino.cli "$APP/Contents/Helpers/fortino"
    sign "$APP"
    codesign --verify --strict --deep "$APP"
    if [[ -n "$NOTARY_PROFILE" ]]; then
        # The app gets its own ticket so it opens offline, including after an in-app update.
        ditto -c -k --keepParent "$APP" "$OUT/Fortino-app.zip"
        notarize "$OUT/Fortino-app.zip"
        rm -f "$OUT/Fortino-app.zip"
        xcrun stapler staple -q "$APP"
        xcrun stapler validate -q "$APP"
        spctl --assess --type execute "$APP"
    fi
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

if [[ -n "$NOTARY_PROFILE" ]]; then
    notarize "$DMG"
    xcrun stapler staple -q "$DMG"
    xcrun stapler validate -q "$DMG"
    spctl --assess --type open --context context:primary-signature "$DMG"
fi

rm -rf "$OUT/dmg"
shasum -a 256 "$DMG"
