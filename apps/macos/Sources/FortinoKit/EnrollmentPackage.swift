// Read deployment metadata from a user-selected image. No installer is launched.
import Darwin
import Foundation

public struct EnrollmentPackage: Sendable {
    public let address: String
    public let installID: String

    public static func read(_ image: URL) throws -> Self {
        let fm = FileManager.default
        let mount = fm.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try fm.createDirectory(at: mount, withIntermediateDirectories: false,
                               attributes: [.posixPermissions: 0o700])
        defer { _ = rmdir(mount.path) }
        try diskImage(["attach", "-readonly", "-nobrowse", "-noautoopen", "-mountpoint", mount.path, image.path])
        let result = Result { try metadata(at: mount) }
        try diskImage(["detach", mount.path])
        return try result.get()
    }

    private static func diskImage(_ args: [String]) throws {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/hdiutil")
        p.arguments = args
        p.standardInput = FileHandle.nullDevice
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        try p.run()
        p.waitUntilExit()
        guard p.terminationStatus == 0 else { throw invalid("Could not " + args[0] + " the disk image.") }
    }

    private static func invalid(_ message: String) -> NSError {
        NSError(domain: "Fortino.Enrollment", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }

    static func metadata(at mount: URL) throws -> Self {
        let entries = (try? FileManager.default.contentsOfDirectory(atPath: mount.path)) ?? []
        if let why = EnrollmentPackageKind.classify(entries: entries).explanation {
            throw invalid(why)
        }
        func readMember(_ name: String, limit: Int) throws -> Data {
            let root = mount.resolvingSymlinksInPath().standardizedFileURL
            let file = root.appendingPathComponent("fctdata/" + name)
            guard file.resolvingSymlinksInPath().standardizedFileURL.path == file.path,
                  try file.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile == true else {
                throw invalid("Missing regular package file " + name)
            }
            let handle = try FileHandle(forReadingFrom: file)
            defer { try? handle.close() }
            let data = try handle.read(upToCount: limit + 1) ?? Data()
            guard !data.isEmpty, data.count <= limit else { throw invalid("Invalid size for " + name) }
            return data
        }
        let custom = try readMember("custom.conf", limit: 65536)
        let plist = try PropertyListSerialization.propertyList(from: custom, format: nil)
        guard let id = (plist as? [String: Any])?["INSTALLUID"] as? String,
              !id.isEmpty, id.utf8.count <= 256,
              id.utf8.allSatisfy({ (33...126).contains($0) && $0 != 124 }) else {
            throw invalid("This package has no supported deployment identifier.")
        }
        let data = try readMember("default.conf", limit: 4 * 1024 * 1024)
        guard let xml = String(data: data, encoding: .utf8), !xml.contains("<!DOCTYPE") else {
            throw invalid("Unsupported package configuration format.")
        }
        let doc = try XMLDocument(xmlString: xml, options: [.nodeLoadExternalEntitiesNever])
        let nodes = try doc.nodes(forXPath: "/forticlient_configuration/endpoint_control/management_servers/server/addresses")
        guard nodes.count == 1, let address = nodes.first?.stringValue,
              case let .success(server?) = parseEms(address) else {
            throw invalid("Expected one EMS management address in this package.")
        }
        return Self(address: server.display, installID: id)
    }
}


public struct EnrollmentReply: Decodable {
    public let status: String
    public let rules: Bool
}

extension DaemonClient {
    public func enroll(_ package: EnrollmentPackage) async throws -> EnrollmentReply {
        struct Params: Encodable {
            let server: String
            let install_uid: String
        }
        return try await call("ems.enroll", Params(server: package.address, install_uid: package.installID))
    }

    /// Registers this Mac with `server` now, without a deployment package (**Register Now**).
    public func register(server: EmsServer) async throws -> EnrollmentReply {
        struct Params: Encodable { let server: String }
        return try await call("ems.enroll", Params(server: server.display))
    }
}

/// This Mac's registration state with one EMS (`ems.status`).
public struct EmsStatus: Decodable, Equatable {
    /// unconfigured, managed-by-forticlient, held-by-forticlient, not-registered, registered,
    /// stale, quarantined.
    public let state: String
    public let registeredAt: Int?
    public let lastKeepalive: Int?
    /// Whether the EMS sent host-verification rules; nil when not registered.
    public let rules: Bool?
    /// Whether a connection key is saved for this server (never the key itself).
    public let key: Bool?
    /// Why the EMS refused the last registration, while this Mac isn't registered.
    public let refusal: EmsRefusal?

    public init(state: String, registeredAt: Int? = nil, lastKeepalive: Int? = nil, rules: Bool? = nil,
                key: Bool? = nil, refusal: EmsRefusal? = nil) {
        self.state = state
        self.registeredAt = registeredAt
        self.lastKeepalive = lastKeepalive
        self.rules = rules
        self.key = key
        self.refusal = refusal
    }

    /// Registered and checked in, yet the EMS sent no rules: it likely doesn't recognize this
    /// Mac, or its policy doesn't cover it. Not shown before the first keepalive, when no
    /// rules are expected yet.
    public var checkedInWithoutRules: Bool {
        (state == "registered" || state == "stale") && lastKeepalive != nil && rules == false
    }
}

/// A registration the EMS refused.
public struct EmsRefusal: Decodable, Equatable {
    /// The reason, with the EMS's own message when it gave one.
    public let reason: String
    /// The EMS wants a connection key, or a different one.
    public let key: Bool

    public init(reason: String, key: Bool) {
        self.reason = reason
        self.key = key
    }
}

extension DaemonClient {
    public func emsStatus(server: EmsServer) async throws -> EmsStatus {
        struct Params: Encodable { let server: String }
        return try await call("ems.status", Params(server: server.display))
    }

    /// What leaving an EMS did.
    public struct LeaveReply: Decodable {
        /// The EMS removed this Mac's device record.
        public let deregistered: Bool
        /// Why the record stayed on the EMS, when there was one.
        public let kept: String?
    }

    /// Leaves `server`, which no profile may still use: the EMS removes this Mac's record, and
    /// the service forgets the server's registration, connection key and approval.
    public func leaveEms(server: EmsServer) async throws -> LeaveReply {
        struct Params: Encodable { let server: String }
        return try await call("ems.leave", Params(server: server.display))
    }

    /// Saves the connection key for `server` (nil removes it). Returns the service's outcome:
    /// saved, removed, none, configured or approval-required.
    public func setEmsKey(server: EmsServer, key: String?) async throws -> String {
        struct Params: Encodable { let server: String; let key: String? }
        struct Reply: Decodable { let status: String }
        let r: Reply = try await call("ems.setKey", Params(server: server.display, key: key))
        return r.status
    }
}
