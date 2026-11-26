# Changelog

What changed in each release of Fortino. Each section is also the release's notes on GitHub and in the app's update window.

## 0.7.1

- **EMS connection key.** Some EMS servers register a Mac only with a connection key (also called the telemetry password) from your IT administrator. When the EMS refuses the registration, EMS Setup and the profile now say so, show the EMS's reason and offer **Enter Connection Key…**, which saves the key for that EMS and registers right away. Before, the app kept offering **Register Now**, which failed the same way. From the terminal: `fortino ems-key set <server>`; `fortino ems-status` shows the refusal.
- **Leaving an EMS.** Deleting the last profile that uses an EMS now offers **Delete and Leave EMS**: the EMS removes this Mac's device record, and Fortino forgets the server's approval and registration on this Mac. **Delete Profile Only** keeps them. A saved connection key is removed as soon as no profile uses its EMS. From the terminal: `fortino ems-leave <server>`.

- **Save password.** Turn on **Save password in Keychain** for a profile and Fortino saves the password in your login keychain once it connects, then fills it in next time. One-time codes are always asked for. If the gateway rejects a saved password, Fortino asks you again instead of retrying it, and offers to replace it. Turning the option off or deleting the profile removes the saved password. A password is saved for the profile's username, so the option needs one. From the terminal: `fortino profile edit <name> --save-password`, and `fortino password save | status | forget <name>`.

## 0.7.0

- **EMS Setup.** A guided checklist for each profile's EMS server: the server, permission on this Mac, registration, compliance and the VPN gateway, each with a tick or a cross. The first step that needs you comes first, with the buttons that fix it. Open it from the profile's EMS row, from **File → EMS Setup…**, or from a failed connection. **Copy Details for IT** gives your administrator what they need.
- **Register now.** Register this Mac with the EMS before connecting, so problems show up before you type your VPN password. Also `fortino ems-register <server>`.
- **FortiClient on the same Mac.** An EMS keeps one registration per Mac. When FortiClient is registered with the same EMS, Fortino no longer registers alongside it (the two would push each other out). EMS Setup offers the ways out: disconnect FortiClient from the EMS, uninstall it, or keep it for that VPN, and updates by itself once FortiClient lets go.
- **Clearer failures.** A gateway that refuses the login because this Mac isn't registered with its EMS now says so, before asking for your password, and suggests why. When the EMS refuses a registration, its own reason is shown.
- **Deployment packages checked.** Enrolling with a FortiClient package for a different EMS than the profile's is blocked, and FortiClient's standard installers, which carry no EMS settings, are explained instead of failing.
- **Registration kept during a session.** If the EMS drops this Mac while the VPN is connected, Fortino registers again and carries on.
- **Profiles window after an update.** The profile list no longer disappears while the "Fortino was updated" notice is shown.

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
