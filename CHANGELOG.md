# Changelog

What changed in each release of Fortino. Each section is also the release's notes on GitHub and in the app's update window.

## 0.6.0

The first public release.

- **Notarized download.** The DMG and the app are signed and notarized, so they open without a Gatekeeper warning.
- **Updates.** Fortino checks for new versions once a day and offers them with the release notes: install now, remind later or skip that version. Check any time with **Fortino → Check for Updates…**, or turn automatic checks off in Settings → General. A connected VPN stays up while the app updates.
- **Intel Macs.** The download now runs on Intel as well as Apple silicon. Intel builds have not been tested on Intel hardware yet; please report what you find.
- **Export to FortiClient.** File → Export to FortiClient… writes your profiles as a FortiClient XML configuration.
- **EMS approval.** Connecting with a profile whose EMS server is not approved yet shows the server and asks you to approve it first.
- **Connect saves your edits.** Connecting from the profile window saves unsaved changes first.
- **Menu-bar icon on a fresh install.** The icon starts near the clock, so a crowded menu bar no longer hides it.
- **Login compatibility.** A gateway whose login page answers with an unexpected status is logged, and the login goes ahead.
