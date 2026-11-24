#!/bin/bash
# Publishes a Fortino release on GitHub: a signed, notarized, universal DMG and the update feed
# (appcast.xml) that installed copies read through Sparkle.
#
#   SIGN_APP="Developer ID Application: NAME (TEAMID)" NOTARY_PROFILE=fortino \
#       scripts/release-macos.sh [--dry-run]
#
# The version is CFBundleShortVersionString in apps/macos/Resources/Info.plist; its release notes
# are the "## <version>" section of CHANGELOG.md. The app reads the feed from the latest release
# (SUFeedURL), so the release is created as a draft with both files and published last.
#
# --dry-run builds and notarizes the DMG and writes the feed and notes to target/package, but
# tags and uploads nothing; repository checks only warn.
#
# Needs: gh (authenticated), rustup with both macOS targets, Sparkle's EdDSA key in the login
# keychain under the account in SPARKLE_ACCOUNT (default "fortino"; see docs/releasing.md).
set -euo pipefail

DRY_RUN=0
case "${1:-}" in
    --dry-run) DRY_RUN=1 ;;
    "") ;;
    *) echo "usage: $0 [--dry-run]" >&2; exit 2 ;;
esac

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REPO="${FORTINO_REPO:-moku-io/fortino}"
PLIST="$ROOT/apps/macos/Resources/Info.plist"
VERSION=$(/usr/libexec/PlistBuddy -c 'Print CFBundleShortVersionString' "$PLIST")
BUILD=$(/usr/libexec/PlistBuddy -c 'Print CFBundleVersion' "$PLIST")
MIN_OS=$(/usr/libexec/PlistBuddy -c 'Print LSMinimumSystemVersion' "$PLIST")
FEED=$(/usr/libexec/PlistBuddy -c 'Print SUFeedURL' "$PLIST")
TAG="v$VERSION"
OUT="$ROOT/target/package"
DMG="$OUT/Fortino-$VERSION.dmg"
SPARKLE_BIN="$ROOT/apps/macos/.build/artifacts/sparkle/Sparkle/bin"
SPARKLE_ACCOUNT="${SPARKLE_ACCOUNT:-fortino}"

problems=0
fail() {
    if [[ $DRY_RUN == 1 ]]; then
        echo "warning: $*" >&2
    else
        echo "error: $*" >&2
        problems=1
    fi
}
die() { echo "error: $*" >&2; exit 1; }

echo "==> Checking release $VERSION (build $BUILD)"
[[ -n "${SIGN_APP:-}" ]] || die "set SIGN_APP to the Developer ID Application identity"
[[ -n "${NOTARY_PROFILE:-}" ]] || die "set NOTARY_PROFILE to a notarytool keychain profile"
command -v gh >/dev/null || die "gh is not installed"
gh auth status >/dev/null 2>&1 || die "gh is not authenticated (gh auth login)"

NOTES=$(awk -v v="$VERSION" '
    /^## / { if (found) exit; split($0, w, " "); if (w[2] == v) { found = 1; next } }
    found { print }' "$ROOT/CHANGELOG.md" | sed -e '/./,$!d' | sed -e :a -e '/^\n*$/{$d;N;ba' -e '}')
[[ "$BUILD" =~ ^[0-9]+$ ]] || die "CFBundleVersion must be a whole number"
[[ -n "$NOTES" ]] || die "CHANGELOG.md has no \"## $VERSION\" section"
[[ "$NOTES" != *"]]>"* ]] || die "the release notes contain \"]]>\""

[[ -z "$(git -C "$ROOT" status --porcelain)" ]] || fail "the working tree has changes; commit them so the DMG matches a commit"
[[ "$(git -C "$ROOT" rev-parse --abbrev-ref HEAD)" == main ]] || fail "not on main"
git -C "$ROOT" fetch --quiet origin main --tags
[[ "$(git -C "$ROOT" rev-parse HEAD)" == "$(git -C "$ROOT" rev-parse origin/main)" ]] || fail "HEAD is not origin/main; push first"
if git -C "$ROOT" rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then fail "tag $TAG exists"; fi
[[ "$(gh repo view "$REPO" --json visibility -q .visibility)" == PUBLIC ]] \
    || fail "$REPO is not public, so installed copies cannot read the feed or download the DMG"

# Sparkle offers an update only when its CFBundleVersion is higher than the installed one.
if current=$(curl -fsSL "$FEED" 2>/dev/null); then
    published=$(sed -n 's:.*<sparkle\:version>\([0-9]*\)</sparkle\:version>.*:\1:p' <<<"$current" | head -1)
    if [[ -n "$published" ]] && (( BUILD <= published )); then
        fail "CFBundleVersion $BUILD is not above the published build $published"
    fi
fi
[[ $problems == 0 ]] || exit 1

"$ROOT/scripts/package-macos.sh"
[[ -f "$DMG" ]] || die "$DMG was not built"
[[ -x "$SPARKLE_BIN/sign_update" ]] || die "Sparkle's tools are missing from $SPARKLE_BIN"

echo "==> Writing the update feed"
printf '%s\n' "$NOTES" >"$OUT/notes.md"
# Prints: sparkle:edSignature="…" length="…"
ENCLOSURE_SIG=$("$SPARKLE_BIN/sign_update" --account "$SPARKLE_ACCOUNT" "$DMG")
[[ "$ENCLOSURE_SIG" == *'sparkle:edSignature="'*'length="'* ]] || die "sign_update failed: $ENCLOSURE_SIG"
PAGE="https://github.com/$REPO/releases/tag/$TAG"
URL="https://github.com/$REPO/releases/download/$TAG/Fortino-$VERSION.dmg"
APPCAST="$OUT/appcast.xml"
cat >"$APPCAST" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle">
  <channel>
    <title>Fortino</title>
    <link>https://github.com/$REPO/releases</link>
    <item>
      <title>Fortino $VERSION</title>
      <pubDate>$(LC_ALL=C date -u '+%a, %d %b %Y %H:%M:%S +0000')</pubDate>
      <sparkle:version>$BUILD</sparkle:version>
      <sparkle:shortVersionString>$VERSION</sparkle:shortVersionString>
      <sparkle:minimumSystemVersion>$MIN_OS</sparkle:minimumSystemVersion>
      <sparkle:fullReleaseNotesLink>$PAGE</sparkle:fullReleaseNotesLink>
      <description sparkle:format="markdown"><![CDATA[
$NOTES
]]></description>
      <enclosure url="$URL" type="application/octet-stream" $ENCLOSURE_SIG/>
    </item>
  </channel>
</rss>
EOF
xmllint --noout "$APPCAST"
# The app requires a signed feed (SURequireSignedFeed): sign_update embeds the signature.
"$SPARKLE_BIN/sign_update" --account "$SPARKLE_ACCOUNT" "$APPCAST" >/dev/null
"$SPARKLE_BIN/sign_update" --account "$SPARKLE_ACCOUNT" --verify "$APPCAST"
SIG=$(sed -n 's/.*sparkle:edSignature="\([^"]*\)".*/\1/p' <<<"$ENCLOSURE_SIG")
"$SPARKLE_BIN/sign_update" --account "$SPARKLE_ACCOUNT" --verify "$DMG" "$SIG"

if [[ $DRY_RUN == 1 ]]; then
    echo "==> Dry run: review $APPCAST and $OUT/notes.md; nothing was tagged or uploaded"
    exit 0
fi

echo "==> Tagging $TAG and publishing"
git -C "$ROOT" tag -a "$TAG" -m "Fortino $VERSION"
git -C "$ROOT" push origin "$TAG"
gh release create "$TAG" -R "$REPO" --draft --verify-tag --title "Fortino $VERSION" \
    --notes-file "$OUT/notes.md" "$DMG" "$APPCAST"
gh release edit "$TAG" -R "$REPO" --draft=false --latest

echo "==> Checking the public feed"
for _ in 1 2 3 4 5 6; do
    if curl -fsSL "$FEED" 2>/dev/null | grep -q "<sparkle:version>$BUILD</sparkle:version>"; then
        echo "Published: $PAGE"
        exit 0
    fi
    sleep 10
done
die "$FEED does not serve build $BUILD yet; check the release page $PAGE"
