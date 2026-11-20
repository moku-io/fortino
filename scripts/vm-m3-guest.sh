#!/bin/bash
# Runs inside the disposable VM as root (called by scripts/vm-m3.sh). Milestone 3: validate the
# native macOS network controller (route, scutil, pfctl) against a real tunnel. No EMS.
# Output never includes secret values, host names or addresses of the deployment.
set -uo pipefail
B="/Volumes/My Shared Files/fortino"
W=/var/root/fortino-m3
X="$B/secrets"

[[ "$(id -u)" == 0 ]] || { echo "needs root"; exit 2; }
[[ "$(sysctl -n kern.hv_vmm_present)" == 1 ]] || { echo "refusing outside a VM"; exit 2; }
export FORTINO_SOCKET="$W/fortinod.sock"

mask() { sed -E 's/\(([A-Za-z0-9.-]+):([0-9]+)\)/(…:\2)/g; s/[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+\.[a-z]{2,}/…/g; s/(host|gateway|server)=[^ ]+/\1=…/g; s/[0-9]{1,3}(\.[0-9]{1,3}){3}/a.b.c.d/g'; }

start_daemon() {
    RUST_LOG=info nohup "$W/fortinod" --config "$W/fortinod.toml" > "$W/fortinod.log" 2>&1 < /dev/null &
    for _ in $(seq 1 50); do [[ -S "$W/fortinod.sock" ]] && return 0; sleep 0.2; done
    echo "daemon did not start"; tail -5 "$W/fortinod.log" | mask; return 1
}
phys() { route -n get default 2>/dev/null | awk '/interface:/ {print $2; exit}'; }
tunif() { comm -13 "$W/if.before" <(ifconfig -l | tr ' ' '\n' | sort) | grep -E '^(utun|ppp)' | head -1; }
snapshot() {
    echo "default_iface=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')"
    echo "pf_anchor_rules=$(pfctl -a com.apple/250.Fortino -sr 2>/dev/null | grep -c .)"
    echo "fortino_dns_keys=$(echo 'list State:/Network/Service/org.fortino.*/DNS' | scutil 2>/dev/null | grep -c subKey)"
    echo "dns_servers=$(scutil --dns 2>/dev/null | awk '/nameserver\[/{print $3}' | sort -u | tr '\n' ',')"
}

case "${1:-}" in
setup)
    mkdir -p "$W/ca" "$W/state"
    install -m 0755 "$B"/fortinod "$B"/fortino "$B"/fortino-sslvpn-worker "$W"/
    [[ -x "$B/fortino-netctl-selftest" ]] && install -m 0755 "$B/fortino-netctl-selftest" "$W/"
    chown root:wheel "$W"/fortino-sslvpn-worker
    # Trust: a pin line makes the worker pin the leaf (GATEWAY-3, wildcard cert reached by IP);
    # otherwise the system CA bundle.
    if [[ -s "$X/pin" ]]; then cp "$X/pin" "$W/ca/system.pem"; else cp /etc/ssl/cert.pem "$W/ca/system.pem"; fi
    ifconfig -l | tr ' ' '\n' | sort > "$W/if.before"
    phys > "$W/phys"
    cat > "$W/fortinod.toml" <<EOT
socket_path = "$W/fortinod.sock"
state_dir = "$W/state"
allowed_uids = [0]

[worker]
path = "$W/fortino-sslvpn-worker"
ca_dir = "$W/ca"
EOT
    chmod 600 "$W/fortinod.toml"
    start_daemon || exit 1
    GW=$(cat "$X/gateway")
    "$W/fortino" profile add M3 --host "${GW%:*}" --port "${GW##*:}" \
        --username "$(cat "$X/username")" > /dev/null
    echo "setup ok: daemon running (real network controller), split profile added, phys=$(cat "$W/phys")"
    ;;
connect)
    ifconfig -l | tr ' ' '\n' | sort > "$W/if.before"
    snapshot > "$W/snap.before"
    if [[ -s "$X/otp" ]]; then
        "$W/fortino" connect M3 --password-fd 3 --otp-fd 4 3< "$X/password" 4< "$X/otp" 2>&1 | mask
    else
        "$W/fortino" connect M3 --password-fd 3 3< "$X/password" 2>&1 | mask
    fi
    "$W/fortino" status 2>&1 | grep -iE "state|connected|error|code" | mask
    ;;
check)
    IF=$(tunif); PH=$(cat "$W/phys")
    echo "tunnel interface: ${IF:-none}"
    [[ -z "$IF" ]] && { echo "no tunnel; aborting checks"; exit 1; }
    echo "A. routes on tunnel: $(netstat -rn -f inet | awk -v i="$IF" '$NF==i' | wc -l | tr -d ' ')"
    GW=$(cat "$X/gateway"); GH="${GW%:*}"
    if [[ "$GH" =~ ^[0-9.]+$ ]]; then
        GIF=$(route -n get "$GH" 2>/dev/null | awk '/interface:/{print $2}')
        echo "A. gateway pinned to physical uplink: $([[ "$GIF" == "$PH" ]] && echo yes || echo "no ($GIF)")"
    fi
    PUB=$(route -n get 1.1.1.1 2>/dev/null | awk '/interface:/{print $2}')
    echo "A. unrelated public prefix off tunnel (split): $([[ "$PUB" != "$IF" ]] && echo yes || echo no)"
    echo "A. IPv6 pf block active: $(pfctl -a com.apple/250.Fortino -sr 2>/dev/null | grep -qi 'block drop' && echo yes || echo no)"
    echo "A. IPv6 egress: $(ping6 -c1 -i1 2001:4860:4860::8888 >/dev/null 2>&1 && echo reachable || echo blocked)"
    URL=$(cat "$X/endpoint" 2>/dev/null)
    if [[ -n "$URL" ]]; then
        H=$(echo "$URL" | sed -E 's#^[a-z]+://##; s#[/:].*##')
        if [[ "$H" =~ ^[0-9.]+$ ]]; then
            echo "A. endpoint route via tunnel: $([[ "$(route -n get "$H" 2>/dev/null | awk '/interface:/{print $2}')" == "$IF" ]] && echo yes || echo no)"
        fi
        echo "A. endpoint HTTP over tunnel: $(curl -sk -m 15 -o /dev/null -w '%{http_code}' "$URL")"
    fi
    echo "--- daemon log (net lines)"
    grep -iE "network|route|controller|connected|apply|journal" "$W/fortinod.log" | tail -12 | mask
    ;;
teardown-check)
    snapshot > "$W/snap.after"
    echo "B. state restored after disconnect: $(diff -q "$W/snap.before" "$W/snap.after" >/dev/null && echo yes || echo no)"
    diff "$W/snap.before" "$W/snap.after" | mask | sed 's/^/   /'
    IF=$(tunif); echo "B. tunnel interface gone: $([[ -z "$IF" ]] && echo yes || echo "no ($IF)")"
    ;;
recover)
    J="$W/state/net-journal.json"
    echo "C. journal entries before kill: $(python3 -c "import json;print(len(json.load(open('$J'))['entries']))" 2>/dev/null || echo '?')"
    echo "C. our state present: tunnel_routes=$(netstat -rn -f inet | awk -v i="$(tunif)" '$NF==i' | wc -l | tr -d ' ') pf_rules=$(pfctl -a com.apple/250.Fortino -sr 2>/dev/null | grep -c .)"
    pkill -9 -x fortinod 2>/dev/null; sleep 1
    pkill -9 -f fortino-sslvpn-worker 2>/dev/null; sleep 1
    start_daemon || exit 1
    sleep 2
    echo "C. journal entries after recover: $(python3 -c "import json;print(len(json.load(open('$J'))['entries']))" 2>/dev/null || echo '?')"
    echo "C. pf rules after recover: $(pfctl -a com.apple/250.Fortino -sr 2>/dev/null | grep -c .)"
    echo "C. recover log:"; grep -iE "recover|reconcile|revert|cleanup" "$W/fortinod.log" | tail -6 | mask
    ;;
dns-selftest)
    if [[ -x "$W/fortino-netctl-selftest" ]]; then "$W/fortino-netctl-selftest" 2>&1 | mask; else echo "D. selftest bin not built; skipping"; fi
    ;;
restart)
    # Restart the daemon (e.g. after pushing a new binary). Reaps any worker first.
    pkill -9 -f fortino-sslvpn-worker 2>/dev/null || true
    pkill -9 -x fortinod 2>/dev/null || true
    sleep 1
    start_daemon && echo "daemon restarted"
    ;;
disconnect)
    "$W/fortino" disconnect 2>&1 | mask
    ;;
log)
    tail -40 "$W/fortinod.log" | mask
    ;;
*)
    echo "usage: vm-m3-guest.sh setup|connect|check|teardown-check|recover|dns-selftest|disconnect|log"
    exit 2
    ;;
esac
