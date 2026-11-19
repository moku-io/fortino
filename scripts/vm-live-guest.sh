#!/bin/bash
# Runs inside the disposable VM as root (called by scripts/vm-live.sh). Output never includes
# secret values, host names or addresses of the deployment.
set -uo pipefail
B="/Volumes/My Shared Files/fortino"
W=/var/root/fortino-live
X="$B/secrets"

[[ "$(id -u)" == 0 ]] || { echo "needs root"; exit 2; }
[[ "$(sysctl -n kern.hv_vmm_present)" == 1 ]] || { echo "refusing outside a VM"; exit 2; }
export FORTINO_SOCKET="$W/fortinod.sock"

mask() { sed -E 's/\(([A-Za-z0-9.-]+):([0-9]+)\)/(…:\2)/g; s/[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+\.[a-z]{2,}/…/g; s/ems=[^ ]+/ems=…/g; s/(host|gateway|server)=[^ ]+/\1=…/g; s/[0-9]{1,3}(\.[0-9]{1,3}){3}/a.b.c.d/g'; }

case "$1" in
setup)
    mkdir -p "$W/ca" "$W/state" "$W/probe"
    install -m 0755 "$B"/fortinod "$B"/fortino "$B"/fortino-sslvpn-worker "$B"/fortino-ems-probe "$W"/
    chown root:wheel "$W"/fortino-sslvpn-worker
    cp /etc/ssl/cert.pem "$W/ca/system.pem"
    EMS=$(cat "$X/ems")
    PIN=$("$W/fortino-ems-probe" "$EMS" --print-pin) || { echo "EMS TLS handshake failed"; exit 1; }
    cat > "$W/fortinod.toml" <<EOT
socket_path = "$W/fortinod.sock"
state_dir = "$W/state"
allowed_uids = [0]

[worker]
path = "$W/fortino-sslvpn-worker"
ca_dir = "$W/ca"

[ems]
settle_secs = 3

[ems.servers."$EMS"]
pin = "$PIN"
register = true
EOT
    chmod 600 "$W/fortinod.toml"
    RUST_LOG=info nohup "$W/fortinod" --config "$W/fortinod.toml" > "$W/fortinod.log" 2>&1 < /dev/null &
    for _ in $(seq 1 50); do [[ -S "$W/fortinod.sock" ]] && break; sleep 0.2; done
    [[ -S "$W/fortinod.sock" ]] || { echo "daemon did not start"; tail -5 "$W/fortinod.log" | mask; exit 1; }
    GW=$(cat "$X/gateway")
    "$W/fortino" profile add Live --host "${GW%:*}" --port "${GW##*:}" \
        --username "$(cat "$X/username")" --ems-server "$EMS" > /dev/null
    echo "setup ok: daemon running, profile added, EMS pinned (sha256 len ${#PIN})"
    "$W/fortino-ems-probe" "$EMS" --pin "$PIN" --state "$W/probe" 2>&1 | sed -E 's/serial=FCTEMS[0-9]+/serial=FCTEMS…/' | mask
    ;;
connect)
    ifconfig -l | tr ' ' '\n' | grep '^utun' | sort > "$W/utun.before"
    "$W/fortino" connect Live --password-fd 3 --otp-fd 4 3< "$X/password" 4< "$X/otp" 2>&1 | mask
    "$W/fortino" status 2>&1 | grep -iE "state|connected|error|code" | mask
    ;;
check)
    IF=$(comm -13 "$W/utun.before" <(ifconfig -l | tr ' ' '\n' | grep '^utun' | sort) | head -1)
    echo "tunnel interface: ${IF:-none}"
    [[ -n "$IF" ]] && echo "routes via tunnel: $(netstat -rn -f inet | awk -v i="$IF" '$NF==i' | wc -l | tr -d ' ')"
    URL=$(cat "$X/endpoint" 2>/dev/null)
    if [[ -n "$URL" ]]; then
        H=$(echo "$URL" | sed -E 's#^[a-z]+://##; s#[/:].*##')
        A=$(dscacheutil -q host -a name "$H" | awk '/ip_address/ {print $2; exit}')
        echo "endpoint name resolves: $([[ -n "$A" ]] && echo yes || echo no)"
        [[ -n "$A" ]] && echo "endpoint route: $(route -n get "$A" 2>/dev/null | awk '/interface:/ {print ($2 == "'"$IF"'") ? "tunnel" : "other"}')"
        echo "endpoint HTTP: $(curl -sk -m 15 -o /dev/null -w '%{http_code}' "$URL")"
    fi
    n=0; ok=0
    for r in $(scutil --dns | awk -v i="$IF" '/nameserver\[/ {ns=$3} /if_index/ && $0 ~ i {print ns}' | sort -u); do
        n=$((n + 1)); ping -c 1 -t 3 "$r" > /dev/null 2>&1 && ok=$((ok + 1))
    done
    echo "tunnel resolvers answering ping: $ok/$n"
    echo "--- EMS log"
    grep -E "EMS|ems|registering|defers|keepalive|host verification" "$W/fortinod.log" | tail -15 | mask
    ;;
log)
    tail -40 "$W/fortinod.log" | mask
    ;;
disconnect)
    "$W/fortino" disconnect 2>&1 | mask
    ;;
deregister)
    EMS=$(cat "$X/ems")
    PIN=$(awk -F'"' '/^pin/ {print $2}' "$W/fortinod.toml")
    "$W/fortino-ems-probe" "$EMS" --pin "$PIN" --state "$W/state/ems" --deregister --yes 2>&1 | mask
    ;;
*)
    echo "usage: vm-live-guest.sh setup|connect|check|log|disconnect|deregister"
    exit 2
    ;;
esac
