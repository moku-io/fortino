// What the local listener receives at the end of a single sign-on: the gateway redirects the
// browser to http://127.0.0.1:<port>/?id=<session id>. Mirrors the rules in
// crates/fortino-proto-sslvpn/src/saml.rs.

import Foundation

/// What a request to the single sign-on listener is.
public enum SamlCallback: Equatable {
    /// The gateway's redirect; `query` (`id=…`) answers the challenge. Secret.
    case login(query: String)
    /// A well-formed request for something else, such as `/favicon.ico`: answer 404.
    case notFound
    /// A request the listener doesn't accept (method, framing or Host): answer 400.
    case bad
}

/// Largest request head the listener reads.
public let maxSamlRequestHead = 8 * 1024
/// Longest callback query string accepted.
public let maxSamlQuery = 2048
/// Longest session id accepted.
public let maxSamlSessionId = 1023

/// Whether `query` (`id=…`; other parameters are ignored) holds exactly one well-formed
/// session id: ASCII letters, digits and `-`.
public func samlQueryHasSessionId(_ query: String) -> Bool {
    guard query.utf8.count <= maxSamlQuery else { return false }
    var found: Substring?
    for part in query.split(separator: "&", omittingEmptySubsequences: false) where part.hasPrefix("id=") {
        if found != nil { return false }
        found = part.dropFirst(3)
    }
    guard let id = found, !id.isEmpty, id.utf8.count <= maxSamlSessionId else { return false }
    return id.utf8.allSatisfy { b in
        (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x5A) || (b >= 0x61 && b <= 0x7A) || b == 0x2D
    }
}

/// Where the blank line ending a request head starts, if it has arrived.
public func samlRequestHeadEnd(_ data: Data) -> Int? {
    let b = [UInt8](data)
    var i = 0
    while i < b.count {
        if b[i] == 0x0A {
            if i + 1 < b.count, b[i + 1] == 0x0A { return i }
            if i + 2 < b.count, b[i + 1] == 0x0D, b[i + 2] == 0x0A { return i > 0 && b[i - 1] == 0x0D ? i - 1 : i }
        }
        i += 1
    }
    return nil
}

/// Classifies a request head (request line and headers) received on 127.0.0.1:`port`. Only
/// `GET /?<query>` with a session id and a Host naming this listener (`127.0.0.1:port` or
/// `localhost:port`) is a login; checking the Host keeps a page that reaches the listener through
/// a rebound DNS name from delivering an id.
public func samlCallbackRequest(_ head: Data, port: Int) -> SamlCallback {
    guard head.count <= maxSamlRequestHead else { return .bad }
    // Lines end at LF, with an optional CR before it. (Swift treats CR LF as one Character, so
    // split the bytes, not the string.)
    var lines: [String] = []
    var current: [UInt8] = []
    for byte in head {
        if byte == 0x0A {
            if current.last == 0x0D { current.removeLast() }
            guard let line = String(bytes: current, encoding: .utf8) else { return .bad }
            lines.append(line)
            current = []
        } else {
            current.append(byte)
        }
    }
    if current.last == 0x0D { current.removeLast() }
    guard let last = String(bytes: current, encoding: .utf8) else { return .bad }
    lines.append(last)

    let parts = lines[0].split(separator: " ", omittingEmptySubsequences: false)
    guard parts.count == 3, parts[2] == "HTTP/1.1" || parts[2] == "HTTP/1.0" else { return .bad }
    var host: String?
    for line in lines.dropFirst() {
        if line.isEmpty { break }
        guard let colon = line.firstIndex(of: ":") else { return .bad }
        if line[..<colon].trimmingCharacters(in: .whitespaces).lowercased() == "host" {
            if host != nil { return .bad }
            host = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
        }
    }
    let hostOK: Bool = {
        guard let host, let colon = host.lastIndex(of: ":"),
              Int(host[host.index(after: colon)...]) == port else { return false }
        let name = host[..<colon]
        return name == "127.0.0.1" || name.lowercased() == "localhost"
    }()
    guard hostOK, parts[0] == "GET" else { return .bad }
    let target = parts[1]
    guard target.hasPrefix("/?") else { return .notFound }
    let query = String(target.dropFirst(2))
    return samlQueryHasSessionId(query) ? .login(query: query) : .notFound
}
