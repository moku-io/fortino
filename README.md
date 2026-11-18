# OpenFortiClient project specification

Build a macOS client that can connect to a FortiGate SSL VPN from an SSH terminal, keep the tunnel up when the terminal closes, and let a menu-bar app observe or disconnect the same session. The first release targets password authentication, optional realm and interactive OTP, IPv4 over TLS, and plain FortiClient XML profile import. SAML and IPsec are outside the project scope.

**Check the gateway before starting a deployment.** It must offer SSL VPN tunnel mode to the account in question. Fortinet removed this mode on all FortiGate models in FortiOS 7.6.3. An imported profile or a reachable HTTPS login page cannot establish compatibility. [Fortinet release notes](https://docs.fortinet.com/document/fortigate/7.6.3/fortios-release-notes/173430/ssl-vpn-tunnel-mode-no-longer-supported)

| Read | Purpose |
| --- | --- |
| [Implementation specification] | Components, interfaces, ownership, build sequence and release criteria |
| [Tunnel backend] | Pinned openfortivpn worker, auth, PPP, macOS networking and gateway checks |
| [Profile import] | Selectors, field mapping, conflict rules, sample XML and expected results |
| [Desktop interface observations] | Traced UI actions in the installed 7.4.4.1831 package |
| [Native investigation] | Tray authentication, packet provider, tools findings and evidence boundaries |

This repository contains the development specification. Start with milestone 0 in the implementation specification. A working client, a real export round trip and a verified gateway combination are future deliverables.
