#!/bin/bash
# Installs the Fortino package in a disposable Tart VM and checks install, upgrade and uninstall.
#
#   scripts/package-macos.sh && scripts/macos-vm-pkg-test.sh [PKG]
#   KEEP_VM=1 scripts/macos-vm-pkg-test.sh   # leave the clone running
#
# Environment as for scripts/macos-vm-test.sh (TART_HOME, FORTINO_VM_BASE).
set -euo pipefail

export TART_HOME="${TART_HOME:-/Volumes/esterno1/tart}"
BASE="${FORTINO_VM_BASE:-ofc-sequoia-base}"
VM="fortino-pkg-$$"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PKG="${1:-$(ls -t "$ROOT"/target/package/Fortino-*.pkg | head -1)}"
STAGE="$(mktemp -d)"

cleanup() {
    if [[ -z "${KEEP_VM:-}" ]]; then
        tart stop "$VM" >/dev/null 2>&1 || true
        tart delete "$VM" >/dev/null 2>&1 || true
    else
        echo "VM kept running: TART_HOME=$TART_HOME tart exec $VM ..." >&2
    fi
    rm -rf "$STAGE"
}
trap cleanup EXIT

cp "$PKG" "$STAGE/Fortino.pkg"
cat > "$STAGE/guest.sh" <<'EOF'
#!/bin/bash
set -uo pipefail
P="/Volumes/My Shared Files/fortino/Fortino.pkg"
export FORTINO_SOCKET=/var/run/fortino/fortinod.sock
fail=0
check() { if eval "$2" >/dev/null 2>&1; then echo "PASS  $1"; else echo "FAIL  $1"; fail=1; fi; }
running() { launchctl print system/org.fortino.fortinod | grep -q "state = running"; }
wait_sock() { for _ in $(seq 1 25); do [[ -S $FORTINO_SOCKET ]] && return 0; sleep 0.2; done; return 1; }

installer -pkg "$P" -target / || fail=1
wait_sock
check "service running" running
check "socket present" "[[ -S $FORTINO_SOCKET ]]"
check "config written" "[[ -f '/Library/Application Support/Fortino/fortinod.toml' ]]"
check "system CA provisioned" "[[ -s '/Library/Application Support/Fortino/ca/system.pem' ]]"
check "worker root-owned" "[[ \$(stat -f %u /usr/local/libexec/fortino/fortino-sslvpn-worker) == 0 ]]"
check "app installed" "[[ -x /Applications/Fortino.app/Contents/MacOS/Fortino ]]"
check "CLI reaches daemon" "fortino status"
check "log level settable" "fortino log-level debug && [[ \$(fortino log-level) == debug ]]"
fortino profile add PkgTest --host vpn.example.org >/dev/null

# A second local account (in staff, not root) is allowed by group and sees only its own profiles.
sysadminctl -addUser fortinotest -password "$(uuidgen)" >/dev/null 2>&1
check "staff user allowed" "sudo -u fortinotest env FORTINO_SOCKET=$FORTINO_SOCKET fortino status"
check "staff user sees own profiles only" "! sudo -u fortinotest env FORTINO_SOCKET=$FORTINO_SOCKET fortino profile list | grep -q PkgTest"
C="/Library/Application Support/Fortino/fortinod.toml"
cp "$C" /tmp/fortinod.toml.bak
dseditgroup -o create fortino
sed -i '' 's/^allowed_groups = .*/allowed_groups = ["fortino"]/' "$C"
launchctl kickstart -k system/org.fortino.fortinod; sleep 1; wait_sock
check "restricted: non-member denied" "! sudo -u fortinotest env FORTINO_SOCKET=$FORTINO_SOCKET fortino status"
dseditgroup -o edit -a fortinotest -t user fortino
check "restricted: member allowed without restart" "sudo -u fortinotest env FORTINO_SOCKET=$FORTINO_SOCKET fortino status"
cp /tmp/fortinod.toml.bak "$C"
launchctl kickstart -k system/org.fortino.fortinod; sleep 1; wait_sock

installer -pkg "$P" -target / >/dev/null || fail=1
wait_sock
check "upgrade: service running" running
check "upgrade: profiles kept" "fortino profile list | grep -q PkgTest"

/usr/local/libexec/fortino/uninstall.sh --purge
check "uninstall: service gone" "! launchctl print system/org.fortino.fortinod"
check "uninstall: files gone" "[[ ! -e /Applications/Fortino.app && ! -e /usr/local/bin/fortino && ! -e /usr/local/libexec/fortino && ! -e /Library/LaunchDaemons/org.fortino.fortinod.plist ]]"
check "uninstall: receipt gone" "! pkgutil --pkg-info org.fortino.pkg"
exit $fail
EOF
chmod +x "$STAGE/guest.sh"

echo "==> cloning $BASE -> $VM" >&2
tart clone "$BASE" "$VM"
tart run --no-graphics --dir="fortino:$STAGE:ro" "$VM" >/dev/null 2>&1 &
for _ in $(seq 1 120); do
    tart exec "$VM" true >/dev/null 2>&1 && break
    sleep 2
done
tart exec "$VM" sw_vers
tart exec "$VM" sudo "/Volumes/My Shared Files/fortino/guest.sh"
