#!/bin/bash
# Installs Fortino from the DMG in a disposable Tart VM, as a user would, and checks it.
#
#   scripts/package-macos.sh && scripts/macos-vm-dmg-test.sh [DMG]
#   KEEP_VM=1 scripts/macos-vm-dmg-test.sh   # leave the clone running
#
# Covers: the app bundle and its signature, the CLI link, the daemon running from inside the app with built-in defaults (no config file), access by group,
# and a tunnel through the mock gateway with the daemon as its own worker (`fortinod --worker`).
# Not covered (needs a logged-in GUI session): SMAppService registration and its approval in
# Login Items, and removal by moving the app to the Trash. Here root starts the bundled daemon
# the way launchd would.
#
# Environment as for scripts/macos-vm-test.sh (TART_HOME, FORTINO_VM_BASE).
set -euo pipefail

export TART_HOME="${TART_HOME:-/Volumes/esterno1/tart}"
BASE="${FORTINO_VM_BASE:-ofc-sequoia-base}"
VM="fortino-dmg-$$"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DMG="${1:-$(ls -t "$ROOT"/target/package/Fortino-*.dmg | head -1)}"
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

(cd "$ROOT" && cargo build --locked -q -p fortino-mock --bin fortino-mock)
cp "$DMG" "$STAGE/Fortino.dmg"
cp "$ROOT/target/debug/fortino-mock" "$ROOT/fixtures/vm/mock-gateway.yaml" "$STAGE/"
cat > "$STAGE/guest.sh" <<'EOF'
#!/bin/bash
set -uo pipefail
export PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
S="/Volumes/My Shared Files/fortino"
APP=/Applications/Fortino.app
SUP="/Library/Application Support/Fortino"
export FORTINO_SOCKET=/var/run/fortino/fortinod.sock
fail=0
check() { if eval "$2" >/dev/null 2>&1; then echo "PASS  $1"; else echo "FAIL  $1"; fail=1; fi; }
as_user() { sudo -u fortinotest env FORTINO_SOCKET=$FORTINO_SOCKET /usr/local/bin/fortino "$@"; }
start_daemon() {
    "$APP/Contents/MacOS/fortinod" >> /tmp/fortinod.log 2>&1 &
    DAEMON=$!
    for _ in $(seq 1 25); do [[ -S $FORTINO_SOCKET ]] && return 0; sleep 0.2; done
    return 1
}
stop_daemon() { kill "$DAEMON" 2>/dev/null; wait "$DAEMON" 2>/dev/null; rm -f "$FORTINO_SOCKET"; }

# Install as a user would: copy the app out of the disk image into Applications, owned by the
# user (here a fresh local account), and link the CLI as "Install Command-Line Tool..." does.
sysadminctl -addUser fortinotest -password "$(uuidgen)" >/dev/null 2>&1
M=$(hdiutil attach -nobrowse -readonly "$S/Fortino.dmg" | awk -F'\t' '/Volumes/ {print $NF}')
ditto "$M/Fortino.app" "$APP" && chown -R fortinotest "$APP"
hdiutil detach -quiet "$M"
mkdir -p /usr/local/bin && ln -sfh "$APP/Contents/Helpers/fortino" /usr/local/bin/fortino
check "app bundle complete" "[[ -x $APP/Contents/MacOS/Fortino && -x $APP/Contents/MacOS/fortinod && -f $APP/Contents/Library/LaunchDaemons/org.fortino.fortinod.plist ]]"
check "app signature valid" "codesign --verify --strict --deep $APP"

start_daemon
check "daemon runs from the app with built-in defaults" "fortino status"
check "log level settable" "fortino log-level debug && [[ \$(fortino log-level) == debug ]]"
fortino profile add PkgTest --host vpn.example.org >/dev/null
check "staff user allowed" "as_user status"
check "staff user sees own profiles only" "! as_user profile list | grep -q PkgTest"
stop_daemon
dseditgroup -o create fortino
printf 'allowed_groups = ["fortino"]\nsocket_group = "staff"\n' > "$SUP/fortinod.toml"
start_daemon
check "restricted: non-member denied" "! as_user status"
dseditgroup -o edit -a fortinotest -t user fortino
check "restricted: member allowed without restart" "as_user status"
stop_daemon
rm -f "$SUP/fortinod.toml"

# A tunnel through the mock gateway: the daemon runs itself as the worker and trusts the pin
# provisioned as the default ("system") trust. The bundle is user-owned, so the worker must run
# from the verified root-owned copy.
IP=$(ipconfig getifaddr en0)
"$S/fortino-mock" fortigate "$S/mock-gateway.yaml" --bind "$IP:10443" > /tmp/mock.out 2>&1 &
MOCK=$!
for _ in $(seq 1 50); do grep -q cert-sha256 /tmp/mock.out && break; sleep 0.2; done
mkdir -p "$SUP/ca"
echo "sha256:$(awk '/cert-sha256/ {print $NF}' /tmp/mock.out)" > "$SUP/ca/system.pem"
start_daemon
fortino profile add Lab --host "$IP" --port 10443 --username alice >/dev/null
fortino connect Lab --password-fd 3 --otp-fd 4 3< <(printf 'hunter2\n') 4< <(printf '123456\n') >/dev/null
check "connect through the bundled worker" "fortino status | grep -qi connected"
check "worker is the verified root-owned copy" "pgrep -f '/libexec/fortinod --worker' && [[ \$(stat -f %u '$SUP/libexec/fortinod') == 0 ]]"
check "ping through the tunnel" "ping -c 2 -t 5 10.99.0.1"
fortino disconnect >/dev/null
check "disconnected" "! pgrep -f 'fortinod --worker'"
stop_daemon
kill $MOCK 2>/dev/null

if [[ $fail != 0 ]]; then echo "--- fortinod.log"; tail -30 /tmp/fortinod.log; fi
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
