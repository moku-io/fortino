#!/bin/bash
# Full-stack test in a disposable Tart VM: builds fortinod, fortino, the native worker and the mock
# gateway, then runs scripts/vm-e2e-guest.sh as root inside a fresh clone and deletes it.
#
#   scripts/macos-vm-e2e.sh            # clone, boot, test, delete
#   KEEP_VM=1 scripts/macos-vm-e2e.sh  # leave the clone running for debugging
#
# TART_HOME (default /Volumes/esterno1/tart) and FORTINO_VM_BASE (default ofc-sequoia-base) as in
# scripts/macos-vm-test.sh.
set -euo pipefail

export TART_HOME="${TART_HOME:-/Volumes/esterno1/tart}"
BASE="${FORTINO_VM_BASE:-ofc-sequoia-base}"
VM="fortino-e2e-$$"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
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

echo "==> building" >&2
(cd "$ROOT" && cargo build --locked -p fortinod -p fortino-cli -p fortino-sslvpn -p fortino-mock --bins)
for b in fortinod fortino fortino-sslvpn-worker fortino-mock; do cp "$ROOT/target/debug/$b" "$STAGE/"; done
cp "$ROOT/fixtures/vm/mock-gateway.yaml" "$ROOT/scripts/vm-e2e-guest.sh" "$STAGE/"

echo "==> cloning $BASE -> $VM" >&2
tart clone "$BASE" "$VM"
tart run --no-graphics --dir="fortino:$STAGE:ro" "$VM" >/dev/null 2>&1 &
for _ in $(seq 1 120); do
    tart exec "$VM" true >/dev/null 2>&1 && break
    sleep 2
done
tart exec "$VM" sw_vers

echo "==> running the full stack as root" >&2
S="/Volumes/My Shared Files/fortino"
tart exec "$VM" sudo env PATH=/usr/bin:/bin:/usr/sbin:/sbin /bin/bash "$S/vm-e2e-guest.sh" "$S"
