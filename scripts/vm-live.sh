#!/bin/bash
# Live run of the full stack against a real gateway and its EMS, inside a disposable Tart VM.
# The VM gets its own hardware UUID, so on the EMS it is a separate device from the host.
#
#   scripts/vm-live.sh up CREDS        build, boot a clone, start fortinod, add the profile
#                                      (contacts nothing but the EMS TLS handshake for its pin)
#   echo CODE | scripts/vm-live.sh connect
#                                      connect; the EMS registration happens here, before login
#   scripts/vm-live.sh check           data-plane checks and EMS log lines (values masked)
#   scripts/vm-live.sh disconnect
#   scripts/vm-live.sh deregister      remove the VM's device record from the EMS
#   scripts/vm-live.sh down            delete the VM and the staged secrets
#
# CREDS is the maintainer's credentials file with an
# `EMS` line. Secrets are staged in a private temporary directory outside the repository, shared
# read-only with the VM, and deleted by `down`. Nothing prints secret values or deployment names.
set -euo pipefail

export TART_HOME="${TART_HOME:-/Volumes/esterno1/tart}"
BASE="${FORTINO_VM_BASE:-ofc-sequoia-base}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STATE="$ROOT/target/vm-live.state"
S="/Volumes/My Shared Files/fortino"

guest() {
    # shellcheck disable=SC1090
    source "$STATE"
    tart exec "$VM" sudo env PATH=/usr/bin:/bin:/usr/sbin:/sbin /bin/bash "$S/vm-live-guest.sh" "$@"
}

field() { grep -i "^$1 *:" "$CREDS" | head -1 | cut -d: -f2- | sed 's/^ *//; s/ *$//'; }

case "${1:-}" in
up)
    CREDS="${2:?credentials file}"
    [[ -e "$STATE" ]] && { echo "already up; run '$0 down' first" >&2; exit 2; }
    (cd "$ROOT" && cargo build --locked -p fortinod -p fortino-cli -p fortino-sslvpn -p fortino-ems --bins)
    STAGE="$(mktemp -d)"
    chmod 700 "$STAGE"
    for b in fortinod fortino fortino-sslvpn-worker fortino-ems-probe; do cp "$ROOT/target/debug/$b" "$STAGE/"; done
    cp "$ROOT/scripts/vm-live-guest.sh" "$STAGE/"
    (
        umask 077
        mkdir "$STAGE/secrets"
        field gateway > "$STAGE/secrets/gateway"
        field username > "$STAGE/secrets/username"
        field password > "$STAGE/secrets/password"
        field ems | sed 's#^https\{0,1\}://##; s#/.*##' > "$STAGE/secrets/ems"
        field 'test endpoint to check if connection succeed' > "$STAGE/secrets/endpoint"
    )
    for f in gateway username password ems; do
        [[ -s "$STAGE/secrets/$f" ]] || { echo "credentials file lacks '$f'" >&2; rm -rf "$STAGE"; exit 2; }
    done
    VM="fortino-live-$$"
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
    rm -f "$STAGE/secrets/otp"
    ;;
check | disconnect | deregister | log)
    guest "$1"
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
