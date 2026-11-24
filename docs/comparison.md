# How Fortino compares

Fortino is still in development: the table shows **target** behaviour for Fortino, and its status column says what works today. Entries for the other clients come from their documentation (November 2026); corrections are welcome.

| | Fortino (status) | openfortivpn | OpenConnect `--protocol=fortinet` | FortiClient VPN (vendor) |
| --- | --- | --- | --- | --- |
| License | GPL-3.0-or-later | GPL-3.0 + OpenSSL exception | LGPL-2.1 | Proprietary |
| Language | Rust daemon, Swift app | C | C | — |
| Password + token code | Yes (password live on one gateway; codes tested against the mock) | Yes | Yes (tokeninfo and HTML forms) | Yes |
| FortiToken Mobile push | Planned | Yes | Not documented | Yes |
| SAML | In development: sign-in in the default browser, from the app and the CLI (tested against the mock); a built-in sign-in window is planned | Yes (`--saml-login`, or openfortivpn-webview) | Not documented | Yes |
| Client certificate | Planned | Yes | Yes | Yes |
| Gateway certificate checks | Strict; fetches intermediates a gateway leaves out; after a warning, trusts one specific certificate per gateway (app) | Strict, or `--trusted-cert` pin | Strict, or `--servercert` pin | Prompt |
| PPP tunnel | Supported by the native worker (no pppd) | Yes (pppd) | Yes (built-in PPP) | Yes |
| Raw-IP "tun" tunnel (FortiOS ≥ 5.6.6 v2 protocol) | Planned | No | No | Yes |
| DTLS | Planned | No | Yes (preferred, TLS fallback) | Yes |
| EMS registration (needed by some gateways) | Per-profile registration and truthful posture | No | No | Yes |
| **Switching gateways switches EMS** (one registration per EMS, chosen by the VPN profile) | **One registration per EMS, selected by the VPN profile** | No EMS | No EMS | No: one EMS per machine; changing to a gateway with another EMS means re-registering |
| FortiClient request headers (`FSV_*`, User-Agent) | In development, default | No | No | Yes |
| Per-domain split DNS | Yes (macOS controller) | Limited (two servers, one suffix) | Via vpnc-script | Yes |
| User-chosen split tunnel: only the subnets you list go through the VPN, the rest of the Internet stays on the Mac's own connection | Planned (today: the gateway's routes) | Partial (`--set-routes=0`, then your own routes) | Via vpnc-script or vpn-slice | Set by the gateway or EMS administrator |
| DNS choice per profile: the gateway's DNS, or keep the Mac's own (like FortiClient's `inherit_local_dns`) | Yes: the gateway's DNS for the domains it names, or the Mac's DNS for every name; VPN DNS for every name is planned | `--set-dns=0` | Via vpnc-script | One global option, not per profile |
| IPv6 block during IPv4 tunnels | Yes (pf anchor, not yet live-tested) | No | Via script | Yes |
| Network rollback after crash | Yes (write-ahead journal) | Partial | Script-dependent | Yes |
| macOS app | Native SwiftUI menu bar | Third-party GUIs | OpenConnect-GUI | Yes |
| Headless CLI | Yes (`fortino`) | Yes | Yes | Limited |
| Security suite (AV, web filter, ZTNA…) | No (out of scope) | No | No | Paid editions |

Why another client: some gateways admit a tunnel only for clients registered with the organization's FortiClient EMS, and no open-source client implements EMS. Fortino will register and report its real state; it never fakes compliance. Ask your IT or security team before registering it with a corporate EMS.

Other related projects: [openfortivpn-go](https://pkg.go.dev/github.com/elizandrodantas/openfortivpn-go) (a Go port) and LivConnect (a multi-protocol desktop wrapper around openfortivpn and OpenConnect).

## Thanks

Fortino stands on the shoulders of the open-source clients that made FortiGate SSL VPNs usable without the vendor client. Thank you to:

- **[openfortivpn](https://github.com/adrienverge/openfortivpn)** (Adrien Vergé and contributors). Its clear implementation of the SSL VPN login and PPP tunnel was our reference for early debugging, and its pinned build proved the PPP path.
- **[OpenConnect](https://www.infradead.org/openconnect/fortinet.html)** (David Woodhouse, Daniel Lenski and contributors), whose Fortinet support documents the protocol, PPP-over-DTLS and the challenge forms.
- The projects around them: **[openfortivpn-webview](https://github.com/gm-vm/openfortivpn-webview)** for SAML login, **[NetworkManager-fortisslvpn](https://gitlab.gnome.org/GNOME/NetworkManager-fortisslvpn)** for Linux desktop integration, and GUIs such as **OpenFortiGUI**, **[OpenFortiVPN GUI](https://e1z0.net/software/openfortivpn-gui)** and **[fcovpn](https://github.com/jiriteach/fcovpn)**.
