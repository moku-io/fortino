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
