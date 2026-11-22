#!/bin/bash
# Read-only macOS diagnostics. Run on the affected Mac before disconnecting.
# With no redirection, write a private report in the user's home directory.
export PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C
umask 077

if [[ $(uname -s) != Darwin || $# != 0 ]]; then
    echo "Usage on macOS: scripts/net-diag.sh" >&2
    exit 2
fi
if [[ -t 1 ]]; then
    report=$(mktemp "$HOME/fortino-net-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX") || exit 1
    echo "Saving network report to $report" >&2
    exec > "$report" || exit 1
fi

# Stock macOS has Perl. The alarm survives exec, including for a stuck DNS lookup.
bounded() {
    /usr/bin/perl -e '$SIG{ALRM} = "DEFAULT"; alarm 5; exec @ARGV or die "exec: $!\n"' -- "$@"
}
section() {
    local title=$1 rc
    shift
    printf '\n### %s\n' "$title"
    bounded "$@" 2>&1
    rc=$?
    case $rc in
        0) ;;
        142) echo '[timed out after 5s]' ;;
        *) printf '[exit %d]\n' "$rc" ;;
    esac
}

section 'Capture time (UTC)' date -u
section 'macOS version' sw_vers
section 'Active IPv4/IPv6 paths' scutil --nwi
section 'Interfaces (including tunnel and VM bridge state)' ifconfig -a
for family in inet inet6; do
    section "$family routing table" netstat -rn -f "$family"
    section "$family default route" route -n get "-$family" default
done

v4=1.1.1.1
v6=2606:4700:4700::1111
section 'IPv4 route to public probe' route -n get -inet "$v4"
section 'IPv6 route to public probe' route -n get -inet6 "$v6"
section 'System DNS resolvers and scopes' scutil --dns
section 'Dynamic-store resolver keys and primary services' scutil <<'STORE'
list State:/Network/Service/.*/DNS
show State:/Network/Global/DNS
show State:/Network/Global/IPv4
show State:/Network/Global/IPv6
STORE

printf '\n### VPN and VM processes (executable names only)\n'
bounded ps -axo pid=,ucomm= | awk 'tolower($2) ~ /forti|ztagent|ztna|pppd|tart|wireguard|tailscale|orbstack|vmnet|virtualization/'
ps_status=${PIPESTATUS[0]}
if (( ps_status != 0 )); then printf '[ps exit %d]\n' "$ps_status"; fi

# Use cached sudo credentials only. Keep report creation under the caller's UID.
pf=(pfctl)
if (( EUID != 0 )); then pf=(sudo -n pfctl); fi
section 'Packet filter status' "${pf[@]}" -s info
section 'Main packet filter rules and anchor references' "${pf[@]}" -s rules
section 'Fortino IPv6 block rules and counters' "${pf[@]}" -a com.apple/250.Fortino -vvs rules

gateway=$(bounded route -n get -inet default 2>/dev/null | awk '$1 == "gateway:" {print $2; exit}')
if [[ $gateway =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    section 'IPv4 default gateway ICMP' ping -n -c 1 "$gateway"
fi
section 'Public IPv4 ICMP' ping -n -c 1 "$v4"
section 'Public IPv6 ICMP' ping6 -n -c 1 "$v6"
section 'Public IPv4 TCP 443 (numeric)' nc -4 -nvz -w 3 "$v4" 443
section 'Public IPv6 TCP 443 (numeric)' nc -6 -nvz -w 3 "$v6" 443
section 'System hostname lookup (may be cached)' dscacheutil -q host -a name apple.com
echo
echo 'Capture complete.'
