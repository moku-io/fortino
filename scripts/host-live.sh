#!/bin/bash
# Live test on the maintainer's own Mac, run BY THE MAINTAINER with sudo. Agents never run this:
# root changes to the host network are off limits to them (AGENTS.md, "Root and the host network").
#
# Fortino's daemon brings up a real utun tunnel while FortiClient's EMS agent, registered and
# tagged on the same EMS, sees the new interface and reports it. Fortino defers to that agent and
# sends nothing to the EMS itself (and could not register even if it tried: register = false).
# The script checks the data plane for a few minutes, then disconnects and compares routes,
# resolver entries and the pf anchor with the state before.
#
#   cargo build -p fortinod -p fortino-cli -p fortino-sslvpn -p fortino-ems --bins   (as yourself)
#   sudo scripts/host-live.sh up CREDS       root-only work dir, start fortinod, add the profile
#   sudo scripts/host-live.sh connect        connect; prompts for the password and the token code
#   sudo scripts/host-live.sh watch [SECS]   data-plane checks every 15 s (default 240)
#   sudo scripts/host-live.sh down           disconnect, stop fortinod, compare with before
#   sudo scripts/host-live.sh log            daemon log lines about EMS and the tunnel
#
# FortiClient's own VPN must be disconnected (its EMS agent stays running). The output of watch,
# down and log masks names and addresses so it can be pasted into a session. If anything goes
# wrong, `down` rolls the network back; a reboot also undoes everything Fortino changes (routes,
# resolver entries and the pf anchor are not persistent).
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
W=/private/var/root/fortino-host-test
FCLOG="/Library/Application Support/Fortinet/FortiClient/Logs/epctrl.log"
export FORTINO_SOCKET="$W/fortinod.sock"

[[ "$(id -u)" == 0 ]] || { echo "run with sudo"; exit 2; }

mask() {
    sed -E 's/\x1b\[[0-9;]*m//g; s/[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+\.[a-z]{2,}/…/g;
        s/[0-9]{1,3}(\.[0-9]{1,3}){3}/a.b.c.d/g; s/([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}/xx:xx/g;
        s/FCTEMS[0-9]+/FCTEMS…/g; s/[0-9A-Fa-f]{32}/<uid>/g'
}
snapshot() {
    { netstat -rn -f inet | awk 'NR>4 && $3 !~ /[WL]/ && $2 !~ /^link#/ {print $1,$2,$3,$4}' | sort
      echo 'list State:/Network/Service/.*/DNS' | scutil
      pfctl -s info 2>/dev/null | awk '/^Status:/ {print $1, $2}'
      pfctl -a com.apple/250.Fortino -s rules 2>/dev/null; } > "$1"
}
field() { grep -i "^$1 *:" "$CREDS" | head -1 | cut -d: -f2- | sed 's/^ *//; s/ *$//'; }
tunnel_if() { comm -13 "$W/utun.before" <(ifconfig -l | tr ' ' '\n' | grep '^utun' | sort) | head -1; }

case "${1:-}" in
up)
    CREDS="${2:?credentials file}"
    if scutil --nc list | grep 'com.fortinet.forticlient' | grep -q '(Connected)'; then
        echo "FortiClient's VPN is connected; disconnect it first (keep FortiClient running)"
        exit 2
    fi
    [[ -e "$W/fortinod.pid" ]] && { echo "already up; run '$0 down' first"; exit 2; }
    for b in fortinod fortino fortino-sslvpn-worker fortino-ems-probe; do
        [[ -x "$ROOT/target/debug/$b" ]] || { echo "build first (as yourself): missing $b"; exit 2; }
    done
    install -d -m 700 -o root -g wheel "$W" "$W/ca" "$W/state"
    for b in fortinod fortino fortino-sslvpn-worker fortino-ems-probe; do
        install -m 755 -o root -g wheel "$ROOT/target/debug/$b" "$W/"
    done
    cp /etc/ssl/cert.pem "$W/ca/system.pem"
    GW=$(field gateway)
    USERNAME=$(field username)
    EMS=$(field ems | sed 's#^https\{0,1\}://##; s#/.*##')
    (umask 077; field 'test endpoint to check if connection succeed' > "$W/endpoint")
    for v in GW USERNAME EMS; do [[ -n "${!v}" ]] || { echo "credentials file lacks $v"; exit 2; }; done
    PIN=$("$W/fortino-ems-probe" "$EMS" --print-pin) || { echo "EMS TLS handshake failed"; exit 1; }
    (umask 077; cat > "$W/fortinod.toml" <<EOT
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
register = false
EOT
)
    snapshot "$W/before"
    { [[ -r "$FCLOG" ]] && wc -l < "$FCLOG" || echo 0; } | tr -d ' ' > "$W/fclog.base"
    RUST_LOG=info nohup "$W/fortinod" --config "$W/fortinod.toml" > "$W/fortinod.log" 2>&1 < /dev/null &
    echo $! > "$W/fortinod.pid"
    for _ in $(seq 1 50); do [[ -S "$W/fortinod.sock" ]] && break; sleep 0.2; done
    [[ -S "$W/fortinod.sock" ]] || { echo "fortinod did not start:"; tail -5 "$W/fortinod.log" | mask; exit 1; }
    "$W/fortino" profile add Live --host "${GW%:*}" --port "${GW##*:}" \
        --username "$USERNAME" --ems-server "$EMS" > /dev/null || exit 1
    echo "FortiClient EMS agent: $("$W/fortino-ems-probe" "$EMS" --forticlient 2>&1 \
        | grep -oE 'running=[a-z]+|registered=[a-z]+|same_uid=[a-z]+|this_ems=[a-z]+' | tr '\n' ' ')"
    echo "up: fortinod running, profile 'Live' added. Next: sudo $0 connect"
    ;;
connect)
    ifconfig -l | tr ' ' '\n' | grep '^utun' | sort > "$W/utun.before"
    "$W/fortino" connect Live
    date +%s > "$W/connected_at"
    "$W/fortino" status 2>&1 | grep -E "State|Connected" | mask
    echo "Next: sudo $0 watch"
    ;;
watch)
    SECS="${2:-240}"
    t0=$(cat "$W/connected_at")
    IF=$(tunnel_if)
    echo "tunnel interface: ${IF:-none}"
    URL=$(cat "$W/endpoint" 2>/dev/null)
    H=$(echo "$URL" | sed -E 's#^[a-z]+://##; s#[/:].*##')
    base=$(cat "$W/fclog.base")
    first_ok=""
    while :; do
        el=$(( $(date +%s) - t0 ))
        A=""; code="-"
        if [[ -n "$H" ]]; then
            A=$(dscacheutil -q host -a name "$H" | awk '/ip_address/ {print $2; exit}')
            code=$(curl -sk -m 8 -o /dev/null -w '%{http_code}' "$URL")
        fi
        seen="?"; noticed="?"
        if [[ -r "$FCLOG" && -n "$IF" ]]; then
            new=$(tail -n +$((base + 1)) "$FCLOG")
            noticed=$(grep -ac "Change in network detected" <<< "$new")
            seen=$(grep -a "NWIFS=" <<< "$new" | grep -c "$IF|")
        fi
        printf '%4ss  name resolves: %-3s  HTTP: %-3s  FortiClient agent: network changes %s, reports with %s %s\n' \
            "$el" "$([[ -n "$A" ]] && echo yes || echo no)" "$code" "$noticed" "${IF:-tunnel}" "$seen"
        [[ "$code" != 000 && "$code" != - && -z "$first_ok" ]] && first_ok=$el
        (( el >= SECS )) && break
        sleep 15
    done
    echo "first HTTP answer after connect: ${first_ok:-never} s"
    ;;
log)
    grep -E "EMS|ems|defer|connected|attempt|stopping" "$W/fortinod.log" | tail -15 | mask
    ;;
down)
    IF=$(tunnel_if 2>/dev/null)
    "$W/fortino" disconnect 2>&1 | mask
    sleep 2
    [[ -e "$W/fortinod.pid" ]] && kill "$(cat "$W/fortinod.pid")" 2>/dev/null
    rm -f "$W/fortinod.pid"
    sleep 1
    snapshot "$W/after"
    if diff -q "$W/before" "$W/after" > /dev/null; then
        echo "network restored: routes, resolver entries and pf anchor identical to before"
    else
        echo "network differs from before in $(diff "$W/before" "$W/after" | grep -c '^[<>]') lines;"
        echo "inspect with: sudo diff $W/before $W/after (FortiClient may also have changed something)"
    fi
    if [[ -n "$IF" ]] && ifconfig "$IF" > /dev/null 2>&1; then
        echo "tunnel interface still present"
    else
        echo "tunnel interface gone"
    fi
    echo "work dir kept for inspection: $W (remove with: sudo rm -rf $W)"
    ;;
*)
    sed -n '2,24p' "$0"
    exit 2
    ;;
esac
