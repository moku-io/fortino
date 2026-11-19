#!/bin/bash
# Runs the root-only macOS controller tests (crates/fortino-platform/tests/macos_root.rs) inside a
# disposable Tart VM, so no test ever changes this Mac's network settings.
#
#   scripts/macos-vm-test.sh            # clone, boot, test, delete
#   KEEP_VM=1 scripts/macos-vm-test.sh  # leave the clone running for debugging
#
# Environment:
#   TART_HOME  where Tart keeps VMs (default /Volumes/esterno1/tart)
#   FORTINO_VM_BASE  base VM to clone (default ofc-sequoia-base)
set -euo pipefail

export TART_HOME="${TART_HOME:-/Volumes/esterno1/tart}"
BASE="${FORTINO_VM_BASE:-ofc-sequoia-base}"
VM="fortino-test-$$"
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

echo "==> building test binary" >&2
bin="$(cd "$ROOT" && cargo test -p fortino-platform --test macos_root --no-run --message-format=json 2>/dev/null |
    python3 -c 'import json,sys
for l in sys.stdin:
    m=json.loads(l)
    if m.get("reason")=="compiler-artifact" and m.get("executable") and m["target"]["name"]=="macos_root":
        print(m["executable"])')"
[[ -n "$bin" ]] || { echo "build failed" >&2; exit 1; }
cp "$bin" "$STAGE/macos_root"

echo "==> cloning $BASE -> $VM" >&2
tart clone "$BASE" "$VM"
tart run --no-graphics --dir="fortino:$STAGE:ro" "$VM" >/dev/null 2>&1 &

echo "==> waiting for the guest agent" >&2
for _ in $(seq 1 120); do
    tart exec "$VM" true >/dev/null 2>&1 && break
    sleep 2
done
tart exec "$VM" sw_vers

echo "==> running tests as root" >&2
tart exec "$VM" sudo env FORTINO_VM_ROOT_TESTS=1 RUST_BACKTRACE=1 \
    "/Volumes/My Shared Files/fortino/macos_root" --test-threads=1 --nocapture "$@"
