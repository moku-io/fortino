// Client-side field checks for immediate feedback. The daemon revalidates everything.

import Foundation

public let defaultEmsPort = 8013

public enum FieldCheck: Equatable {
    case ok
    case error(String)
}

/// Checks a host name or IPv4 address (no IPv6, no scheme).
public func checkHost(_ s: String) -> FieldCheck {
    let h = s.trimmingCharacters(in: .whitespaces)
    if h.isEmpty { return .error("Enter a host name or IPv4 address") }
    if h.count > 253 { return .error("Host name is too long") }
    if h.contains(":") || h.hasPrefix("[") { return .error("IPv6 addresses are not supported") }
    if h.allSatisfy({ $0.isNumber || $0 == "." }) {
        let parts = h.split(separator: ".", omittingEmptySubsequences: false)
        let ok = parts.count == 4 && parts.allSatisfy { p in
            guard !p.isEmpty, p.count <= 3, let n = Int(p) else { return false }
            return n <= 255
        }
        return ok ? .ok : .error("Invalid IPv4 address")
    }
    let name = h.hasSuffix(".") ? String(h.dropLast()) : h
    for label in name.split(separator: ".", omittingEmptySubsequences: false) {
        let valid = !label.isEmpty && label.count <= 63
            && label.allSatisfy { ($0.isASCII && ($0.isLetter || $0.isNumber)) || $0 == "-" }
            && !label.hasPrefix("-") && !label.hasSuffix("-")
        if !valid { return .error("Invalid host name") }
    }
    return .ok
}

/// Parses `host[:port]` for the EMS server field. Empty input means "no EMS server".
public func parseEms(_ s: String) -> Result<EmsServer?, ProtoError> {
    let t = s.trimmingCharacters(in: .whitespaces)
    if t.isEmpty { return .success(nil) }
    if t.contains("://") || t.contains("/") || t.contains("@") || t.contains("?") || t.contains(where: { $0.isWhitespace || $0.isNewline }) {
        return .failure(ProtoError(code: "invalid_address", message: "Enter a host name or IPv4 address with an optional port", field: "ems"))
    }
    var host = t
    var port = defaultEmsPort
    if let idx = t.lastIndex(of: ":") {
        host = String(t[..<idx])
        let p = String(t[t.index(after: idx)...])
        guard !p.isEmpty, p.count <= 5, p.allSatisfy(\.isNumber), let n = Int(p), (1...65535).contains(n) else {
            return .failure(ProtoError(code: "invalid_port", message: "Port must be between 1 and 65535", field: "ems"))
        }
        port = n
    }
    if case let .error(m) = checkHost(host) {
        return .failure(ProtoError(code: "invalid_address", message: m, field: "ems"))
    }
    // Match the daemon's normalized host:port, also used for per-server approval.
    if host.hasSuffix(".") { host.removeLast() }
    return .success(EmsServer(host: host.lowercased(), port: port))
}

/// Checks a realm: one path segment of printable ASCII without `/?#%\`.
public func checkRealm(_ s: String) -> FieldCheck {
    if s.isEmpty { return .ok }
    if s.count > 128 { return .error("Realm is too long") }
    let bad: Set<Character> = ["/", "?", "#", "%", "\\", " "]
    let ok = s.allSatisfy { $0.isASCII && !$0.isWhitespace && !bad.contains($0) && ($0.asciiValue ?? 0) > 32 && ($0.asciiValue ?? 127) < 127 }
    return ok ? .ok : .error("Realm must be a single word without / ? # %")
}

/// Checks a gateway port.
public func checkPort(_ s: String) -> FieldCheck {
    guard let n = Int(s.trimmingCharacters(in: .whitespaces)), (1...65535).contains(n) else {
        return .error("Port must be between 1 and 65535")
    }
    return .ok
}
