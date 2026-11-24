// Self-checks for FortinoKit. Run with `swift run FortinoKitSelfTest`; exits non-zero on failure.
// (The Command Line Tools ship without XCTest, so this avoids needing Xcode.)

import Foundation
import FortinoKit

var failures = 0
func check(_ cond: @autoclosure () throws -> Bool, _ what: String, line: Int = #line) {
    let ok = (try? cond()) ?? false
    if !ok {
        failures += 1
        print("FAIL line \(line): \(what)")
    }
}

// Framing
let f = encodeFrame(Data("hello".utf8))
check(Array(f.prefix(4)) == [0, 0, 0, 5], "frame header")
check(frameLength(f.prefix(4)) == 5, "frame length")
check(frameLength(Data([0, 4, 0, 1])) == nil, "oversized frame rejected")

// EMS field
check(try parseEms("ems.example.org:9016").get() == EmsServer(host: "ems.example.org", port: 9016), "ems with port")
check(try parseEms("EMS.example.org").get() == EmsServer(host: "ems.example.org", port: 8013), "ems default port")
check(try parseEms("  ").get() == nil, "empty ems")
for bad in ["ems:0", "ems:65536", "ems:", "https://ems", "a b", "ems/x", "[::1]:1"] {
    if case .success = parseEms(bad) { check(false, "accepted \(bad)") }
}
check(checkRealm("Staff") == .ok && checkRealm("a/b") != .ok, "realm")
check(checkPort("10443") == .ok && checkPort("0") != .ok, "port")

check(try parseEms("EMS.example.org.:8013").get()?.display == "ems.example.org:8013", "canonical EMS approval name")

// Daemon build check
check(checkDaemonBuild(app: nil, daemon: "a") == .current, "development app skips the check")
check(checkDaemonBuild(app: "a", daemon: "a") == .current, "same build")
check(checkDaemonBuild(app: "b", daemon: "a") == .different(daemon: "a"), "other build")
check(checkDaemonBuild(app: "b", daemon: nil) == .predatesBuildIds, "daemon without build IDs")
if let h = try? JSONDecoder().decode(HelloResult.self, from: Data(#"{"version":1,"daemonInstance":"i","uid":501}"#.utf8)) {
    check(h.build == nil, "hello without build")
} else {
    check(false, "hello decodes without build")
}
if let r = try? JSONDecoder().decode(DaemonRestartResult.self, from: Data(#"{"when":"afterDisconnect"}"#.utf8)) {
    check(r.when == .afterDisconnect, "restart when")
} else {
    check(false, "restart result decodes")
}

// EMS without rules
check(EmsStatus(state: "registered", lastKeepalive: 5, rules: false).checkedInWithoutRules, "no rules after keepalive")
check(!EmsStatus(state: "registered", lastKeepalive: nil, rules: false).checkedInWithoutRules, "no keepalive yet")
check(!EmsStatus(state: "registered", lastKeepalive: 5, rules: true).checkedInWithoutRules, "rules present")
check(!EmsStatus(state: "not-registered").checkedInWithoutRules, "not registered")

// Status decoding
let j = #"{"daemonInstance":"i","seq":3,"state":"awaiting-input","attemptId":"a1","challenge":{"id":"c1","kind":"otp","prompt":"Token code","expiresInSecs":119},"ipPolicy":"split-ipv4"}"#
if let s = try? JSONDecoder().decode(Status.self, from: Data(j.utf8)) {
    check(s.state == .awaitingInput, "state")
    check(s.challenge?.kind == .otp && s.challenge?.kind.isSecret == true, "challenge")
} else {
    check(false, "status decodes")
}

// EMS status decoding
let ej = #"{"state":"registered","registeredAt":1,"lastKeepalive":2}"#
let es = try? JSONDecoder().decode(EmsStatus.self, from: Data(ej.utf8))
check(es?.state == "registered" && es?.lastKeepalive == 2, "EMS status decodes")

// Spec encoding omits nil fields (the daemon rejects unknown/null shapes)
let spec = ProfileSpec(name: "GATEWAY-2", endpoint: Endpoint(host: "vpn.example.org"))
if let d = try? JSONEncoder().encode(spec),
   let o = try? JSONSerialization.jsonObject(with: d) as? [String: Any],
   let ep = o["endpoint"] as? [String: Any] {
    check(o["description"] == nil, "nil description omitted")
    check(ep["port"] as? Int == 443 && ep["realm"] == nil, "endpoint encoding")
} else {
    check(false, "spec encodes")
}

// DNS mode: the default is left out (older services reject unknown fields); "local" round-trips.
var localSpec = spec
localSpec.dnsMode = .local
if let d0 = try? JSONEncoder().encode(spec),
   let o0 = try? JSONSerialization.jsonObject(with: d0) as? [String: Any],
   let d1 = try? JSONEncoder().encode(localSpec),
   let o1 = try? JSONSerialization.jsonObject(with: d1) as? [String: Any] {
    check(o0["dnsMode"] == nil, "default DNS mode omitted")
    check(o1["dnsMode"] as? String == "local", "local DNS mode encoded")
    check((try? JSONDecoder().decode(ProfileSpec.self, from: d1))?.dnsMode == .local, "DNS mode decodes")
} else {
    check(false, "DNS mode encodes")
}

// Single sign-on: the challenge decodes with its sign-in page.
let sj = #"{"daemonInstance":"i","seq":4,"state":"awaiting-input","attemptId":"a1","challenge":{"id":"c1","kind":"saml","prompt":"Single sign-on","expiresInSecs":299,"saml":{"url":"https://vpn.example.org/remote/saml/start?redirect=1","callbackPort":8020}}}"#
if let s = try? JSONDecoder().decode(Status.self, from: Data(sj.utf8)) {
    check(s.challenge?.kind == .saml && s.challenge?.kind.isSecret == true, "saml challenge")
    check(s.challenge?.saml?.callbackPort == 8020, "saml callback port")
    check(s.challenge?.saml?.url.hasPrefix("https://") == true, "saml sign-in page")
} else {
    check(false, "saml status decodes")
}

// Single sign-on: what the local listener accepts (same rules as the Rust listener).
func requestHead(_ lines: [String]) -> Data { Data(lines.joined(separator: "\r\n").utf8) }
let localHost = "Host: 127.0.0.1:8020"
check(samlCallbackRequest(requestHead(["GET /?id=abc-1 HTTP/1.1", localHost]), port: 8020)
      == .login(query: "id=abc-1"), "callback login")
check(samlCallbackRequest(requestHead(["GET /?id=abc&x=1 HTTP/1.1", "host: LOCALHOST:8020"]), port: 8020)
      == .login(query: "id=abc&x=1"), "localhost callback")
check(samlCallbackRequest(Data("GET /?id=abc HTTP/1.1\nHost: 127.0.0.1:8020".utf8), port: 8020)
      == .login(query: "id=abc"), "bare LF")
check(samlCallbackRequest(requestHead(["GET /favicon.ico HTTP/1.1", localHost]), port: 8020) == .notFound, "favicon")
check(samlCallbackRequest(requestHead(["GET /?id=a!b HTTP/1.1", localHost]), port: 8020) == .notFound, "bad id")
check(samlCallbackRequest(requestHead(["GET /?id=abc HTTP/1.1", "Host: evil.example:8020"]), port: 8020) == .bad, "rebound host")
check(samlCallbackRequest(requestHead(["GET /?id=abc HTTP/1.1", "Host: 127.0.0.1:9000"]), port: 8020) == .bad, "other port")
check(samlCallbackRequest(requestHead(["GET /?id=abc HTTP/1.1", localHost, localHost]), port: 8020) == .bad, "two hosts")
check(samlCallbackRequest(requestHead(["POST /?id=abc HTTP/1.1", localHost]), port: 8020) == .bad, "post")
check(samlCallbackRequest(requestHead(["GET /?id=abc HTTP/1.1"]), port: 8020) == .bad, "no host")
check(samlCallbackRequest(Data([0xff, 0xfe]), port: 8020) == .bad, "not UTF-8")
check(samlQueryHasSessionId("x=1&id=Ab-9"), "session id among parameters")
check(!samlQueryHasSessionId("id=a&id=b") && !samlQueryHasSessionId("x=1") && !samlQueryHasSessionId("id="),
      "missing, repeated or empty id")
check(samlRequestHeadEnd(Data("GET / HTTP/1.1\r\nA: b\r\n\r\nrest".utf8)) == 20, "head end CRLF")
check(samlRequestHeadEnd(Data("GET / HTTP/1.1\nA: b\n\nrest".utf8)) == 19, "head end LF")
check(samlRequestHeadEnd(Data("GET / HTTP/1.1\r\n".utf8)) == nil, "no head end yet")

// Sign-in method round-trips through credentialMode; an unknown one reads as password.
var ssoSpec = spec
ssoSpec.signIn = .saml
check(ssoSpec.credentialMode == "saml" && ssoSpec.signIn == .saml, "sign-in method")
var futureSpec = spec
futureSpec.credentialMode = "certificate"
check(futureSpec.signIn == .password, "unknown method reads as password")

// Live daemon round trip, when FORTINO_SOCKET points at a development daemon.
if let path = ProcessInfo.processInfo.environment["FORTINO_SOCKET"] {
    let sem = DispatchSemaphore(value: 0)
    Task {
        do {
            let c = try DaemonClient(path: path)
            _ = try await c.hello()
            let st = try await c.status()
            check(!st.daemonInstance.isEmpty, "live status")
            _ = try await c.profiles()
        } catch {
            check(false, "live daemon: \(error)")
        }
        sem.signal()
    }
    sem.wait()
}

print(failures == 0 ? "FortinoKit self-test passed" : "\(failures) failure(s)")
exit(failures == 0 ? 0 : 1)
