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

// EMS setup steps
do {
    let ems = EmsServer(host: "ems.example.org", port: 9016)
    func input(_ state: String?, rules: Bool? = nil, ka: Int? = nil, check: EmsServerCheck = .reachable(trusted: true),
               last: String? = nil, connected: Bool = false) -> EmsSetupInput {
        let lr = last.flatMap { try? JSONDecoder().decode(LastResult.self, from: Data(#"{"attemptId":"a","code":"unsupported_policy","message":"\#($0)"}"#.utf8)) }
        return EmsSetupInput(server: ems, serverCheck: check,
                             status: state.map { EmsStatus(state: $0, lastKeepalive: ka, rules: rules) },
                             lastResult: lr, connected: connected)
    }
    func states(_ i: EmsSetupInput) -> [EmsStepState] { i.steps.map(\.state) }

    check(input("unconfigured").roadblock?.action == .approve, "unapproved: approve first")
    check(input("not-registered").roadblock?.action == .registerNow, "approved: register now")
    check(input("not-registered").roadblock?.secondary == .enrollWithPackage, "package as the alternative")
    check(input("held-by-forticlient").roadblock?.id == .registration, "FortiClient holds the registration")
    check(input("held-by-forticlient").roadblock?.state == .blocked, "held is a roadblock, not a todo")
    check(input("held-by-forticlient").roadblock?.fixes.map(\.action) == [.openFortiClient, .uninstallFortiClient, nil], "held offers three ways out")
    check(input("held-by-forticlient").roadblock?.watches == true, "held re-checks by itself")
    check(input("not-registered").roadblock?.watches == false, "todo steps wait for the user")
    check(input("quarantined").roadblock?.state == .blocked, "quarantined")
    check(input("registered", rules: true, ka: 1).roadblock == nil, "all set")
    check(states(input("registered", rules: true, ka: 1)) == [.done, .done, .done, .done, .waiting], "registered with rules")
    check(input("registered", rules: false, ka: 1).steps[3].state == .warning, "no rules after check-in")
    check(input("registered", rules: false).steps[3].state == .waiting, "no rules before check-in")
    check(input("managed-by-forticlient").roadblock == nil, "FortiClient same device")
    check(input(nil, check: .unreachable("No answer.")).roadblock?.id == .server, "unreachable server first")
    check(input("unconfigured", check: .checking).roadblock?.action == .approve, "checking doesn't block")
    let refused = emsRegistrationRequiredPrefix + ": it refused the login without this Mac's EMS serial (HTTP 503)"
    check(input("not-registered", last: refused).steps[4].state == .blocked, "gateway refused, not registered")
    check(input("registered", rules: true, ka: 1, last: refused).roadblock?.action == .connect, "registered since: connect again")
    check(input("registered", rules: true, ka: 1, connected: true).steps[4].state == .done, "connected")
    check(input("registered", rules: true, ka: 1, last: "credentials rejected").steps[4].state == .waiting, "other failures aren't EMS roadblocks")
}

// Enrollment image kinds
check(EnrollmentPackageKind.classify(entries: ["Install.mpkg", "fctdata", "Uninstall.app"]) == .deployment, "deployment package")
check(EnrollmentPackageKind.classify(entries: ["FortiClientInstaller.app"]) == .onlineInstaller, "online installer")
check(EnrollmentPackageKind.classify(entries: ["Install.mpkg", "Uninstall.app"]) == .plainInstaller, "installer without fctdata")
check(EnrollmentPackageKind.classify(entries: ["README"]) == .unknown, "unknown image")
check(EnrollmentPackageKind.onlineInstaller.explanation?.contains("EMS Setup") == true, "online installer points to EMS Setup")
check(EmsServer(host: "a.example", port: 1).isSameServer(as: EmsServer(host: "a.example", port: 1)), "same name")
check(!EmsServer(host: "a.example", port: 1).isSameServer(as: EmsServer(host: "a.example", port: 2)), "other port")
check(EmsServer(host: "127.0.0.1", port: 8013).isSameServer(as: EmsServer(host: "localhost", port: 8013)), "name and address of one server")
check(!EmsServer(host: "127.0.0.1", port: 8013).isSameServer(as: EmsServer(host: "192.0.2.1", port: 8013)), "different addresses")

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
    check(s.challenge?.push == nil, "no push hint from a service that doesn't send one")
} else {
    check(false, "status decodes")
}

// A code prompt that offers a push (FortiToken Mobile): the panel offers Send Push.
let pj = #"{"id":"c2","kind":"otp","prompt":"Token code","push":true,"expiresInSecs":119}"#
check((try? JSONDecoder().decode(Challenge.self, from: Data(pj.utf8)))?.push == true, "push hint decodes")

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

// Save password: left out when off (older services reject unknown fields); on round-trips.
var savingSpec = spec
savingSpec.savePassword = true
if let d0 = try? JSONEncoder().encode(spec),
   let o0 = try? JSONSerialization.jsonObject(with: d0) as? [String: Any],
   let d1 = try? JSONEncoder().encode(savingSpec),
   let o1 = try? JSONSerialization.jsonObject(with: d1) as? [String: Any] {
    check(o0["savePassword"] == nil, "save password omitted when off")
    check(o1["savePassword"] as? Bool == true, "save password encoded")
    check((try? JSONDecoder().decode(ProfileSpec.self, from: d1))?.savePassword == true, "save password decodes")
} else {
    check(false, "save password encodes")
}

// Errors of the bundled CLI: with --json they come on standard output, notes on standard error.
let cliError = Data(#"{"v":1,"error":{"code":"internal","message":"the login keychain: locked"}}"#.utf8)
check(cliFailure(stdout: cliError, stderr: "fortino: note: something\n") == "the login keychain: locked",
      "CLI error read from the JSON envelope")
check(cliFailure(stdout: Data(), stderr: "fortino was not found\n") == "fortino was not found",
      "CLI error falls back to standard error")
check(cliFailure(stdout: Data(), stderr: " ") == nil, "no CLI error text")

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
