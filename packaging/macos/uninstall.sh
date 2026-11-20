#!/bin/sh
# Removes Fortino. Keeps profiles and configuration unless --purge is given.
#   sudo /usr/local/libexec/fortino/uninstall.sh [--purge]
set -u
[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 2; }
LABEL=org.fortino.fortinod

if launchctl print "system/$LABEL" >/dev/null 2>&1; then
    # Disconnect first so routes, DNS and the pf anchor are restored by the daemon.
    FORTINO_SOCKET=/var/run/fortino/fortinod.sock /usr/local/bin/fortino disconnect || true
    launchctl bootout "system/$LABEL" 2>/dev/null || true
fi
pkill -x Fortino 2>/dev/null || true

rm -f "/Library/LaunchDaemons/$LABEL.plist" /usr/local/bin/fortino
rm -rf /Applications/Fortino.app /var/run/fortino
if [ "${1:-}" = "--purge" ]; then
    rm -rf "/Library/Application Support/Fortino" /Library/Logs/Fortino
    echo "Removed Fortino, its profiles, configuration and logs."
else
    echo "Removed Fortino. Profiles and configuration remain in /Library/Application Support/Fortino (use --purge to delete)."
fi
pkgutil --forget org.fortino.pkg >/dev/null 2>&1 || true
rm -rf /usr/local/libexec/fortino
