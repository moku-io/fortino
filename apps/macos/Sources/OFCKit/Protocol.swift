// Control protocol v1 types. Mirrors crates/ofc-core/src/proto.rs and crates/ofc-config.

import Foundation

public let protocolVersion = 1

public struct EmsServer: Codable, Equatable, Hashable {
    public var host: String
    public var port: Int
    public init(host: String, port: Int) {
        self.host = host
        self.port = port
    }
    public var display: String { "\(host):\(port)" }
}

public struct Endpoint: Codable, Equatable, Hashable {
    public var host: String
    public var port: Int
    public var realm: String?
    public var ems: EmsServer?
    public init(host: String, port: Int = 443, realm: String? = nil, ems: EmsServer? = nil) {
        self.host = host
        self.port = port
        self.realm = realm
        self.ems = ems
    }
}

public enum IpPolicy: String, Codable, CaseIterable, Identifiable {
    case splitIpv4 = "split-ipv4"
    case fullIpv4 = "full-ipv4"
    public var id: String { rawValue }
    public var label: String {
        switch self {
        case .splitIpv4: return "Split IPv4 (gateway routes only)"
        case .fullIpv4: return "Full IPv4 (IPv6 not tunneled)"
        }
    }
}

public struct ProfileSpec: Codable, Equatable {
    public var name: String
    public var description: String?
    public var usernameHint: String?
    public var endpoint: Endpoint
    public var credentialMode: String
    public var ipPolicy: IpPolicy
    public var trustId: String

    public init(name: String, endpoint: Endpoint) {
        self.name = name
        self.description = nil
        self.usernameHint = nil
        self.endpoint = endpoint
        self.credentialMode = "password"
        self.ipPolicy = .splitIpv4
        self.trustId = "system"
    }
}

public struct Profile: Codable, Identifiable, Equatable {
    public var id: String
    public var owner: Int
    public var revision: Int
    public var spec: ProfileSpec
}

public enum SessionState: String, Codable {
    case idle
    case starting
    case authenticating
    case awaitingInput = "awaiting-input"
    case configuring
    case connected
    case stopping
    case recoveryRequired = "recovery-required"
    case inUse = "in-use"

    public var isActive: Bool {
        switch self {
        case .starting, .authenticating, .awaitingInput, .configuring, .connected, .stopping:
            return true
        default:
            return false
        }
    }

    public var label: String {
        switch self {
        case .idle: return "Disconnected"
        case .starting: return "Connecting…"
        case .authenticating: return "Signing in…"
        case .awaitingInput: return "Waiting for sign-in"
        case .configuring: return "Configuring network…"
        case .connected: return "Connected"
        case .stopping: return "Disconnecting…"
        case .recoveryRequired: return "Network recovery required"
        case .inUse: return "VPN in use"
        }
    }
}

public enum ChallengeKind: String, Codable {
    case username
    case password
    case otp
    public var isSecret: Bool { self != .username }
}

public struct Challenge: Codable, Equatable {
    public var id: String
    public var kind: ChallengeKind
    public var prompt: String
    public var expiresInSecs: Int
}

public struct LastResult: Codable, Equatable {
    public var attemptId: String
    public var code: String?
    public var message: String
}

public struct Status: Codable, Equatable {
    public var daemonInstance: String
    public var seq: Int
    public var state: SessionState
    public var attemptId: String?
    public var profileId: String?
    public var profileName: String?
    public var gateway: String?
    public var ipPolicy: IpPolicy?
    public var assignedIp: String?
    public var interface: String?
    public var connectedSince: Int?
    public var challenge: Challenge?
    public var lastResult: LastResult?
}

public struct ProtoError: Codable, Error, Equatable, LocalizedError {
    public var code: String
    public var message: String
    public var field: String?
    public var currentRevision: Int?

    public init(code: String, message: String, field: String? = nil) {
        self.code = code
        self.message = message
        self.field = field
        self.currentRevision = nil
    }

    public var errorDescription: String? { message }
}

public struct HelloParams: Codable {
    public var versions: [Int]
    public var client: String
}

public struct HelloResult: Codable {
    public var version: Int
    public var daemonInstance: String
    public var uid: Int
}

public struct Empty: Codable {
    public init() {}
}

public struct ProfileListResult: Codable {
    public var storeRevision: Int
    public var profiles: [Profile]
}

public struct ConnectParams: Codable {
    public var profileId: String
    public var revision: Int
    public var requestKey: String
    public var username: String?

    public init(profileId: String, revision: Int, requestKey: String, username: String?) {
        self.profileId = profileId
        self.revision = revision
        self.requestKey = requestKey
        self.username = username
    }
}

public struct ConnectResult: Codable {
    public var attemptId: String
    public var state: SessionState
    public var seq: Int
}

public enum Event {
    case status(Status)
    case resyncRequired
}
