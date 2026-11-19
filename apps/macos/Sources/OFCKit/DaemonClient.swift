// Unix-socket client for ofcd: 4-byte big-endian length-prefixed JSON frames.

import Darwin
import Foundation

public let defaultSocketPath = "/var/run/fortino/ofcd.sock"
public let maxFrame = 256 * 1024

/// Encodes a frame: 4-byte big-endian length followed by the payload.
public func encodeFrame(_ payload: Data) -> Data {
    var len = UInt32(payload.count).bigEndian
    var out = Data(bytes: &len, count: 4)
    out.append(payload)
    return out
}

/// Decodes the length prefix. Returns nil when the frame is over the limit.
public func frameLength(_ header: Data) -> Int? {
    guard header.count == 4 else { return nil }
    let n = header.reduce(0) { ($0 << 8) | Int($1) }
    return n <= maxFrame ? n : nil
}

struct Request<P: Encodable>: Encodable {
    let v: Int
    let id: String
    let method: String
    let params: P
}

/// One connection to the daemon. Thread-safe; callbacks arrive on a background thread.
public final class DaemonClient: @unchecked Sendable {
    private let fd: Int32
    private let lock = NSLock()
    private var pending: [String: (Result<Data, ProtoError>) -> Void] = [:]
    private var nextId = 1
    private var closed = false
    public var onEvent: ((Event) -> Void)?
    public var onClose: (() -> Void)?

    /// Connects to the socket. Does not perform hello; call `hello()`.
    public init(path: String) throws {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw ProtoError(code: "service_unavailable", message: "socket failed") }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        let cap = MemoryLayout.size(ofValue: addr.sun_path)
        guard bytes.count < cap else {
            close(fd)
            throw ProtoError(code: "service_unavailable", message: "socket path too long")
        }
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            for (i, b) in bytes.enumerated() { raw[i] = b }
            raw[bytes.count] = 0
        }
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        if rc != 0 {
            let err = errno
            close(fd)
            if err == EACCES || err == EPERM {
                throw ProtoError(code: "permission_denied", message: "Not allowed to use the VPN service")
            }
            throw ProtoError(code: "service_unavailable", message: "The VPN service is not running")
        }
        var on: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
        self.fd = fd
        let t = Thread { [weak self] in self?.readLoop() }
        t.name = "ofcd-reader"
        t.start()
    }

    deinit { shutdownSocket() }

    /// Closes the connection; pending calls fail.
    public func shutdownSocket() {
        lock.lock()
        let wasClosed = closed
        closed = true
        lock.unlock()
        if !wasClosed { Darwin.shutdown(fd, SHUT_RDWR) }
    }

    private func readExact(_ n: Int) -> Data? {
        var buf = Data(count: n)
        var got = 0
        while got < n {
            let r = buf.withUnsafeMutableBytes { raw in
                read(fd, raw.baseAddress! + got, n - got)
            }
            if r <= 0 { return nil }
            got += r
        }
        return buf
    }

    private func readLoop() {
        while true {
            guard let h = readExact(4), let n = frameLength(h), let body = readExact(n) else { break }
            handle(body)
        }
        lock.lock()
        closed = true
        let waiters = pending
        pending = [:]
        lock.unlock()
        close(fd)
        for (_, w) in waiters {
            w(.failure(ProtoError(code: "service_unavailable", message: "Lost connection to the VPN service")))
        }
        onClose?()
    }

    private func handle(_ body: Data) {
        guard let obj = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else { return }
        if let id = obj["id"] as? String {
            lock.lock()
            let w = pending.removeValue(forKey: id)
            lock.unlock()
            if let e = obj["error"], let d = try? JSONSerialization.data(withJSONObject: e),
               let pe = try? JSONDecoder().decode(ProtoError.self, from: d) {
                w?(.failure(pe))
            } else {
                let r = obj["result"] ?? [String: Any]()
                let d = (try? JSONSerialization.data(withJSONObject: r, options: [.fragmentsAllowed])) ?? Data("{}".utf8)
                w?(.success(d))
            }
        } else if let ev = obj["event"] as? [String: Any], let type = ev["type"] as? String {
            switch type {
            case "status":
                if let s = ev["status"], let d = try? JSONSerialization.data(withJSONObject: s),
                   let st = try? JSONDecoder().decode(Status.self, from: d) {
                    onEvent?(.status(st))
                }
            case "resync-required":
                onEvent?(.resyncRequired)
            default:
                break
            }
        }
    }

    private func send(_ data: Data) -> Bool {
        let frame = encodeFrame(data)
        return frame.withUnsafeBytes { raw -> Bool in
            var off = 0
            while off < frame.count {
                let w = write(fd, raw.baseAddress! + off, frame.count - off)
                if w <= 0 { return false }
                off += w
            }
            return true
        }
    }

    /// Calls a method and decodes its result.
    public func call<P: Encodable, R: Decodable>(_ method: String, _ params: P, as: R.Type = R.self) async throws -> R {
        let data: Data = try await withCheckedThrowingContinuation { cont in
            lock.lock()
            if closed {
                lock.unlock()
                cont.resume(throwing: ProtoError(code: "service_unavailable", message: "Not connected to the VPN service"))
                return
            }
            let id = "g\(nextId)"
            nextId += 1
            pending[id] = { cont.resume(with: $0.mapError { $0 as Error }) }
            // Serialize writes under the lock so frames never interleave.
            let req = Request(v: protocolVersion, id: id, method: method, params: params)
            let ok = (try? JSONEncoder().encode(req)).map(send) ?? false
            if !ok { pending.removeValue(forKey: id) }
            lock.unlock()
            if !ok {
                cont.resume(throwing: ProtoError(code: "service_unavailable", message: "Lost connection to the VPN service"))
            }
        }
        return try JSONDecoder().decode(R.self, from: data)
    }

    // MARK: Convenience

    public func hello() async throws -> HelloResult {
        try await call("hello", HelloParams(versions: [protocolVersion], client: "Fortino.app"))
    }

    public func status() async throws -> Status { try await call("status", Empty()) }
    public func subscribe() async throws -> Status { try await call("subscribe", Empty()) }
    public func profiles() async throws -> ProfileListResult { try await call("profile.list", Empty()) }

    struct CreateParams: Encodable { let spec: ProfileSpec }
    struct UpdateParams: Encodable { let id: String; let revision: Int; let spec: ProfileSpec }
    struct DeleteParams: Encodable { let id: String; let revision: Int }
    struct RespondParams: Encodable { let attemptId: String; let challengeId: String; let value: String }
    struct DisconnectParams: Encodable { let attemptId: String }

    public func create(_ spec: ProfileSpec) async throws -> Profile {
        try await call("profile.create", CreateParams(spec: spec))
    }

    public func update(_ id: String, revision: Int, _ spec: ProfileSpec) async throws -> Profile {
        try await call("profile.update", UpdateParams(id: id, revision: revision, spec: spec))
    }

    public func delete(_ id: String, revision: Int) async throws {
        let _: Empty = try await call("profile.delete", DeleteParams(id: id, revision: revision))
    }

    public func connect(_ p: ConnectParams) async throws -> ConnectResult {
        try await call("connect", p)
    }

    public func respond(attempt: String, challenge: String, value: String) async throws {
        let _: Empty = try await call("respond", RespondParams(attemptId: attempt, challengeId: challenge, value: value))
    }

    public func disconnect(attempt: String) async throws {
        let _: Empty = try await call("disconnect", DisconnectParams(attemptId: attempt))
    }
}
