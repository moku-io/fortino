#!/bin/bash
# Runs inside the disposable VM as root (called by scripts/macos-vm-e2e.sh). Full stack:
# mock gateway on the VM's own address → fortinod (macOS controller) → fortino-sslvpn-worker (utun)
# → fortino connect; then checks routes, DNS, the IPv6 block and traffic, disconnects and checks
# that everything is restored. A second round repeats it with the profile keeping the Mac's DNS.
set -uo pipefail
B="${1:?binary dir}"
W="$(mktemp -d /tmp/fortino-e2e.XXXX)"
fail=0
check() { if eval "$2"; then echo "PASS  $1"; else echo "FAIL  $1"; fail=1; fi; }
snapshot() {
    { netstat -rn -f inet | awk 'NR>4 && $3 !~ /[WL]/ && $2 !~ /^link#/ {print $1,$2,$3,$4}' | sort
      echo 'list State:/Network/Service/.*/DNS' | scutil
      pfctl -s info 2>/dev/null | awk '/^Status:/ {print $1, $2}'
      pfctl -a com.apple/250.Fortino -s rules 2>/dev/null; } > "$1"
}

[[ "$(id -u)" == 0 ]] || { echo "needs root"; exit 2; }
[[ "$(sysctl -n kern.hv_vmm_present)" == 1 ]] || { echo "refusing outside a VM"; exit 2; }

IP=$(ipconfig getifaddr en0)
install -m 0755 "$B"/fortinod "$B"/fortino "$B"/fortino-sslvpn-worker "$B"/fortino-mock "$W"/
mkdir -p "$W/ca" "$W/state"

"$W/fortino-mock" fortigate "$B/mock-gateway.yaml" --bind "$IP:10443" > "$W/mock.out" 2>&1 &
MOCK=$!
for _ in $(seq 1 50); do grep -q cert-sha256 "$W/mock.out" && break; sleep 0.2; done
PIN=$(awk '/cert-sha256/ {print $NF}' "$W/mock.out")
echo "sha256:$PIN" > "$W/ca/system.pem"

cat > "$W/fortinod.toml" <<EOT
socket_path = "$W/fortinod.sock"
state_dir = "$W/state"
allowed_uids = [0]

[worker]
path = "$W/fortino-sslvpn-worker"
ca_dir = "$W/ca"
EOT
chown root:wheel "$W"/fortino-sslvpn-worker
snapshot "$W/before"
RUST_LOG=info "$W/fortinod" --config "$W/fortinod.toml" > "$W/fortinod.log" 2>&1 &
DAEMON=$!
for _ in $(seq 1 50); do [[ -S "$W/fortinod.sock" ]] && break; sleep 0.2; done
export FORTINO_SOCKET="$W/fortinod.sock"

UTUNS_BEFORE=$(ifconfig -l | tr ' ' '\n' | grep '^utun' | sort)
"$W/fortino" profile add Lab --host "$IP" --port 10443 --username alice >/dev/null
"$W/fortino" connect Lab --password-fd 3 --otp-fd 4 3< <(printf 'hunter2\n') 4< <(printf '123456\n')
check "connect succeeds" '"$W/fortino" status | grep -qi connected'
IF=$(comm -13 <(echo "$UTUNS_BEFORE") <(ifconfig -l | tr ' ' '\n' | grep '^utun' | sort) | head -1)
check "new utun interface ($IF) with 10.212.134.200" 'ifconfig "$IF" 2>/dev/null | grep -q "inet 10.212.134.200"'
check "split route 10.99/16 via the tunnel" 'route -n get 10.99.1.1 | grep -q "interface: $IF"'
check "other traffic stays on en0" 'route -n get 1.1.1.1 | grep -q "interface: en0"'
check "split DNS for intra.example" 'scutil --dns | grep -A3 "intra.example" | grep -q 10.0.0.54'
check "IPv6 block loaded" 'pfctl -a com.apple/250.Fortino -s rules 2>/dev/null | grep -q "block drop quick inet6"'
check "ping through the tunnel" 'ping -c 2 -t 5 10.99.0.1 >/dev/null'

"$W/fortino" disconnect
sleep 1
snapshot "$W/after"
check "network restored after disconnect" 'diff -u "$W/before" "$W/after"'
check "no utun left" '! ifconfig "$IF" >/dev/null 2>&1'

# The same profile keeping the Mac's DNS: same routes, none of the gateway's DNS settings.
"$W/fortino" profile edit Lab --dns local >/dev/null
check "profile shows the Mac's own DNS" '"$W/fortino" profile show Lab | grep -q "^DNS:.*own DNS"'
UTUNS_BEFORE=$(ifconfig -l | tr ' ' '\n' | grep '^utun' | sort)
"$W/fortino" connect Lab --password-fd 3 --otp-fd 4 3< <(printf 'hunter2\n') 4< <(printf '123456\n')
check "local DNS: connect succeeds" '"$W/fortino" status | grep -qi connected'
IF=$(comm -13 <(echo "$UTUNS_BEFORE") <(ifconfig -l | tr ' ' '\n' | grep '^utun' | sort) | head -1)
check "local DNS: split route 10.99/16 still via the tunnel ($IF)" 'route -n get 10.99.1.1 | grep -q "interface: $IF"'
check "local DNS: no resolver for intra.example" '! scutil --dns | grep -q "intra.example"'
check "local DNS: no Fortino resolver keys" '! echo "list State:/Network/Service/.*/DNS" | scutil | grep -qi fortino'
check "local DNS: IPv6 block still loaded" 'pfctl -a com.apple/250.Fortino -s rules 2>/dev/null | grep -q "block drop quick inet6"'
check "local DNS: ping through the tunnel" 'ping -c 2 -t 5 10.99.0.1 >/dev/null'
"$W/fortino" disconnect
sleep 1
snapshot "$W/after-local"
check "local DNS: network restored after disconnect" 'diff -u "$W/before" "$W/after-local"'

# Stopping the service while connected (an uninstall, launchctl bootout): it disconnects and
# restores the network before it exits, so nothing is left for a recovery that may never run.
UTUNS_BEFORE=$(ifconfig -l | tr ' ' '\n' | grep '^utun' | sort)
"$W/fortino" connect Lab --password-fd 3 --otp-fd 4 3< <(printf 'hunter2\n') 4< <(printf '123456\n')
check "SIGTERM: connected first" '"$W/fortino" status | grep -qi connected'
IF=$(comm -13 <(echo "$UTUNS_BEFORE") <(ifconfig -l | tr ' ' '\n' | grep '^utun' | sort) | head -1)
kill -TERM $DAEMON
for _ in $(seq 1 75); do kill -0 $DAEMON 2>/dev/null || break; sleep 0.2; done
check "SIGTERM: the service exited" '! kill -0 $DAEMON 2>/dev/null'
snapshot "$W/after-term"
check "SIGTERM: network restored before exiting" 'diff -u "$W/before" "$W/after-term"'
check "SIGTERM: no utun left" '! ifconfig "$IF" >/dev/null 2>&1'
check "SIGTERM: nothing left in the journal" 'grep -q "\"entries\": \[\]" "$W/state/net-journal.json"'

kill $DAEMON $MOCK 2>/dev/null
if [[ $fail != 0 ]]; then
    echo "--- fortinod.log (tail)"; tail -30 "$W/fortinod.log"
fi
exit $fail
