#!/bin/bash
# Milestone 3: validate the native macOS network controller against a REAL tunnel, inside a
# disposable Tart VM. No EMS. Target a password-only gateway that passes data (GATEWAY-3).
#
#   scripts/vm-m3.sh up CREDS        build, boot a clone, start fortinod (real controller), add profile
#   echo CODE | scripts/vm-m3.sh connect   connect (CODE only if the gateway issues an OTP)
#   scripts/vm-m3.sh check           data-plane / route / IPv6 checks while connected
#   scripts/vm-m3.sh disconnect      disconnect, then verify the host network is restored
#   scripts/vm-m3.sh recover         kill the daemon mid-tunnel and confirm the journal reverts
#   scripts/vm-m3.sh dns             resolver-path selftest against live scutil
#   scripts/vm-m3.sh down            delete the VM and staged secrets
#
# CREDS is the maintainer's credentials file WITHOUT an EMS line. Secrets
# are staged in a private temp dir outside the repo, shared read-only, and deleted by `down`.
# Nothing prints secret values or deployment names.
set -euo pipefail

export TART_HOME="${TART_HOME:-/Volumes/esterno1/tart}"
BASE="${FORTINO_VM_BASE:-ghcr.io/cirruslabs/macos-sequoia-xcode:26.6}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STATE="$ROOT/target/vm-m3.state"
S="/Volumes/My Shared Files/fortino"

guest() {
    # shellcheck disable=SC1090
    source "$STATE"
    # The --dir mount caches files, so push the current guest script into the VM each call
    # rather than trusting the mounted copy. Secrets and binaries stay on the mount (static).
    tart exec -i "$VM" sh -c 'cat > /tmp/vm-m3-guest.sh' < "$ROOT/scripts/vm-m3-guest.sh"
    tart exec "$VM" sudo env PATH=/usr/bin:/bin:/usr/sbin:/sbin /bin/bash /tmp/vm-m3-guest.sh "$@"
}
field() { grep -i "^$1 *:" "$CREDS" | head -1 | cut -d: -f2- | sed 's/^ *//; s/ *$//'; }

case "${1:-}" in
up)
    CREDS="${2:?credentials file}"
    [[ -e "$STATE" ]] && { echo "already up; run '$0 down' first" >&2; exit 2; }
    (cd "$ROOT" && cargo build --locked -p fortinod -p fortino-cli -p fortino-sslvpn --bins)
    STAGE="$(mktemp -d)"; chmod 700 "$STAGE"
    for b in fortinod fortino fortino-sslvpn-worker fortino-sslvpn-probe; do cp "$ROOT/target/debug/$b" "$STAGE/"; done
    # Optional: the resolver-path selftest bin, if it has been built.
    [[ -x "$ROOT/target/debug/fortino-netctl-selftest" ]] && cp "$ROOT/target/debug/fortino-netctl-selftest" "$STAGE/"
    cp "$ROOT/scripts/vm-m3-guest.sh" "$STAGE/"
    (
        umask 077
        mkdir "$STAGE/secrets"
        field gateway > "$STAGE/secrets/gateway"
        field username > "$STAGE/secrets/username"
        field password > "$STAGE/secrets/password"
        : > "$STAGE/secrets/otp"
        field 'test endpoint to check if connection succeed' > "$STAGE/secrets/endpoint"
        # Pin the leaf on the host (it has the probe and reaches the gateway) when the gateway is
        # addressed by IP with a non-matching cert. One `sha256:<hex>` line -> worker pins it.
        GW="$(field gateway)"
        if [[ "${GW%:*}" =~ ^[0-9.]+$ ]]; then
            "$ROOT/target/debug/fortino-sslvpn-probe" "$CREDS" --print-pin | sed 's/^/sha256:/' > "$STAGE/secrets/pin" || : > "$STAGE/secrets/pin"
        else
            : > "$STAGE/secrets/pin"
        fi
    )
    for f in gateway username password; do
        [[ -s "$STAGE/secrets/$f" ]] || { echo "credentials file lacks '$f'" >&2; rm -rf "$STAGE"; exit 2; }
    done
    VM="fortino-m3-$$"
    printf 'VM=%q\nSTAGE=%q\n' "$VM" "$STAGE" > "$STATE"
    tart clone "$BASE" "$VM"
    nohup tart run --no-graphics --dir="fortino:$STAGE:ro" "$VM" >/dev/null 2>&1 &
    for _ in $(seq 1 120); do tart exec "$VM" true >/dev/null 2>&1 && break; sleep 2; done
    tart exec "$VM" sw_vers
    guest setup
    ;;
connect)
    # shellcheck disable=SC1090
    source "$STATE"
    (umask 077; head -c 16 | tr -cd '0-9' > "$STAGE/secrets/otp")
    guest connect || true
    rm -f "$STAGE/secrets/otp"; : > "$STAGE/secrets/otp"
    ;;
check | recover | log | restart)
    guest "$1"
    ;;
push-daemon)
    # shellcheck disable=SC1090
    source "$STATE"
    (cd "$ROOT" && cargo build --locked -q -p fortinod --bin fortinod)
    tart exec -i "$VM" sudo sh -c 'cat > /var/root/fortino-m3/fortinod && chmod 755 /var/root/fortino-m3/fortinod' < "$ROOT/target/debug/fortinod"
    guest restart
    ;;
dns)
    guest dns-selftest
    ;;
disconnect)
    guest disconnect || true
    guest teardown-check
    ;;
down)
    # shellcheck disable=SC1090
    source "$STATE"
    tart stop "$VM" >/dev/null 2>&1 || true
    tart delete "$VM" >/dev/null 2>&1 || true
    rm -rf "$STAGE" "$STATE"
    echo "deleted $VM and the staged secrets"
    ;;
*)
    sed -n '2,20p' "$0"
    exit 2
    ;;
esac
