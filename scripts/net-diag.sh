#!/bin/bash
# Read-only snapshot of this Mac's network state, for "the Internet stopped working" moments.
# Changes nothing. Run with sudo to include pf (firewall) state:
#   sudo scripts/net-diag.sh > ~/Desktop/net-diag.txt
# Review before sharing: it contains local addresses and resolver names.
s() { echo; echo "### $*"; "$@" 2>&1; }
s date
s sw_vers
s route -n get default
s route -n get 1.1.1.1
s netstat -rn -f inet
s netstat -rn -f inet6
s scutil --dns
s scutil --nwi
echo; echo "### dynamic-store DNS keys"; echo 'list State:/Network/Service/.*/DNS' | scutil
echo; echo "### global DNS"; printf 'show State:/Network/Global/DNS\nshow State:/Network/Global/IPv4\n' | scutil
s ifconfig
if [[ $(id -u) == 0 ]]; then
    s pfctl -s info
    s pfctl -s rules
    s pfctl -s nat
    s pfctl -s Anchors -v
fi
echo; echo "### VPN-related processes"
ps axo user,pid,comm | grep -iE "forti|ztagent|ztna|openfortivpn|pppd|fortino|tart|wireguard|tailscale|orbstack" | grep -v grep
s ping -c 2 -t 3 "$(route -n get default 2>/dev/null | awk '/gateway:/ {print $2}')"
s ping -c 2 -t 3 1.1.1.1
s dscacheutil -q host -a name apple.com
