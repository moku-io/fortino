// The guided EMS setup: the chain a profile's EMS needs (server, approval on this Mac,
// registration, compliance, gateway), each link's state and the one action that moves it on.
// Pure logic, so the self-test covers every state the window can show.

import Foundation

/// Start of a connect failure caused by a missing EMS serial (the daemon's wording).
public let emsRegistrationRequiredPrefix = "gateway requires EMS registration"

public enum EmsStepID: String, CaseIterable, Sendable {
    case server, approval, registration, compliance, gateway
}

public enum EmsStepState: Equatable, Sendable {
    /// Satisfied.
    case done
    /// Waiting on an earlier step, or checked later (when connecting).
    case waiting
    /// Being checked.
    case checking
    /// The user can do this now.
    case todo
    /// Something outside the user's normal actions is in the way.
    case blocked
    /// Works, with a caveat worth reading.
    case warning
}

public enum EmsAction: Equatable, Sendable {
    case checkAgain
    case editProfile
    case approve
    case registerNow
    case enrollWithPackage
    case connect
    case openFortiClient
    case uninstallFortiClient
    case copyDetails
}

/// One way out of a blocked step: what to do, how, and the button that starts it.
public struct EmsFix: Equatable, Sendable {
    public let title: String
    public let detail: String
    public let action: EmsAction?
}

public struct EmsStep: Equatable, Sendable {
    public let id: EmsStepID
    public let state: EmsStepState
    public let title: String
    public let detail: String
    /// The main action for this step, if any.
    public let action: EmsAction?
    /// A secondary action, if any.
    public let secondary: EmsAction?
    /// For a blocked step: the ways out, in order of preference.
    public var fixes: [EmsFix] = []
    /// The window re-checks by itself while this step is shown, so the user only has to act.
    public var watches = false
}

/// What the app learned about the EMS server's address.
public enum EmsServerCheck: Equatable, Sendable {
    case checking
    case reachable(trusted: Bool)
    case unreachable(String)
}

public struct EmsSetupInput: Equatable {
    public var server: EmsServer
    public var serverCheck: EmsServerCheck
    /// `ems.status` for the server; nil while loading or when the service is unavailable.
    public var status: EmsStatus?
    /// The last attempt's result, only if it was this profile's.
    public var lastResult: LastResult?
    /// This profile is connected right now.
    public var connected: Bool

    public init(server: EmsServer, serverCheck: EmsServerCheck, status: EmsStatus?,
                lastResult: LastResult?, connected: Bool) {
        self.server = server
        self.serverCheck = serverCheck
        self.status = status
        self.lastResult = lastResult
        self.connected = connected
    }
}

public extension EmsSetupInput {
    /// The steps in order.
    var steps: [EmsStep] {
        [serverStep, approvalStep, registrationStep, complianceStep, gatewayStep]
    }

    /// The first step that needs the user, if any: the roadblock the window leads with.
    var roadblock: EmsStep? {
        steps.first { $0.state == .todo || $0.state == .blocked }
    }

    private var approved: Bool? {
        status.map { $0.state != "unconfigured" }
    }

    private var registered: Bool {
        guard let s = status?.state else { return false }
        return ["registered", "stale", "managed-by-forticlient"].contains(s)
    }

    private var serverStep: EmsStep {
        let title = "EMS server"
        switch serverCheck {
        case .checking:
            return EmsStep(id: .server, state: .checking, title: title,
                           detail: "Checking \(server.display)…", action: nil, secondary: nil)
        case .reachable(true):
            return EmsStep(id: .server, state: .done, title: title,
                           detail: "\(server.display) answers, and macOS trusts its certificate.",
                           action: nil, secondary: nil)
        case .reachable(false):
            return EmsStep(id: .server, state: .done, title: title,
                           detail: "\(server.display) answers. macOS doesn't trust its certificate, so you'll be shown it to confirm when you allow the server.",
                           action: nil, secondary: nil)
        case .unreachable(let why):
            return EmsStep(id: .server, state: .blocked, title: title,
                           detail: "\(why) Check the address with your IT administrator; it is usually a host name and a port such as 8013 or 9016.",
                           action: .checkAgain, secondary: .editProfile)
        }
    }

    private var approvalStep: EmsStep {
        let title = "Permission on this Mac"
        switch approved {
        case nil:
            return EmsStep(id: .approval, state: .checking, title: title,
                           detail: "Asking the Fortino service…", action: nil, secondary: nil)
        case false?:
            return EmsStep(id: .approval, state: .todo, title: title,
                           detail: "Fortino registers this Mac only with servers a Mac administrator has allowed. You'll be asked for this Mac's administrator password, not for anything from IT.",
                           action: .approve, secondary: nil)
        case true?:
            return EmsStep(id: .approval, state: .done, title: title,
                           detail: "Fortino may register this Mac with this server.",
                           action: nil, secondary: nil)
        }
    }

    private var registrationStep: EmsStep {
        let title = "Registration"
        guard approved == true, let s = status?.state else {
            return EmsStep(id: .registration, state: .waiting, title: title,
                           detail: "After the server is allowed on this Mac.", action: nil, secondary: nil)
        }
        switch s {
        case "registered", "stale":
            return EmsStep(id: .registration, state: .done, title: title,
                           detail: "This Mac is registered with the EMS. Fortino checks in while the VPN is connected.",
                           action: nil, secondary: nil)
        case "managed-by-forticlient":
            return EmsStep(id: .registration, state: .done, title: title,
                           detail: "FortiClient's EMS agent manages this Mac on this EMS, and Fortino uses that registration.",
                           action: nil, secondary: nil)
        case "held-by-forticlient":
            var step = EmsStep(id: .registration, state: .blocked, title: title,
                               detail: "FortiClient on this Mac is registered with this EMS, and the EMS allows one registration per Mac: if Fortino registered too, the two would keep pushing each other out. Quitting FortiClient isn't enough, because its EMS agent keeps running. Choose one:",
                               action: nil, secondary: nil)
            step.fixes = [
                EmsFix(title: "Disconnect FortiClient from the EMS",
                       detail: "In FortiClient, open Zero Trust Telemetry and click Disconnect. FortiClient stays installed for other uses. If Disconnect is missing or locked, your IT administrator has to allow it.",
                       action: .openFortiClient),
                EmsFix(title: "Uninstall FortiClient",
                       detail: "If Fortino replaces FortiClient on this Mac. Its VPN profiles go with it, so import them into Fortino first (File > Import from FortiClient).",
                       action: .uninstallFortiClient),
                EmsFix(title: "Keep FortiClient for this VPN",
                       detail: "Connect to this gateway with FortiClient instead of Fortino. Nothing to change here.",
                       action: nil),
            ]
            step.watches = true
            return step
        case "quarantined":
            var step = EmsStep(id: .registration, state: .blocked, title: title,
                               detail: "Your IT administrator quarantined this Mac on the EMS. Only they can release it.",
                               action: nil, secondary: nil)
            step.fixes = [
                EmsFix(title: "Contact your IT administrator",
                       detail: "Send them the details of this setup; they release the Mac in the EMS console.",
                       action: .copyDetails),
            ]
            step.watches = true
            return step
        default: // not-registered
            return EmsStep(id: .registration, state: .todo, title: title,
                           detail: "Registering creates a device record for this Mac on the EMS, which your IT administrator can see. Register now to find problems before you enter your VPN password; otherwise Fortino registers when you connect.",
                           action: .registerNow, secondary: .enrollWithPackage)
        }
    }

    private var complianceStep: EmsStep {
        let title = "Compliance"
        guard registered, let st = status else {
            return EmsStep(id: .compliance, state: .waiting, title: title,
                           detail: "After this Mac is registered.", action: nil, secondary: nil)
        }
        if st.state == "managed-by-forticlient" {
            return EmsStep(id: .compliance, state: .done, title: title,
                           detail: "FortiClient reports this Mac's compliance to the EMS.",
                           action: nil, secondary: nil)
        }
        if st.rules == true {
            return EmsStep(id: .compliance, state: .done, title: title,
                           detail: "The EMS sent its compliance rules. Fortino reports this Mac's results, so the EMS can tag it for the gateway.",
                           action: nil, secondary: nil)
        }
        if st.checkedInWithoutRules {
            return EmsStep(id: .compliance, state: .warning, title: title,
                           detail: "The EMS sent no compliance rules for this Mac. It may not recognize this Mac yet, or its policy may not cover it. If the VPN connects but nothing loads, ask your IT administrator to assign this Mac, or enroll with their deployment package.",
                           action: .enrollWithPackage, secondary: nil)
        }
        return EmsStep(id: .compliance, state: .waiting, title: title,
                       detail: "The EMS sends its rules after it first hears from this Mac.",
                       action: nil, secondary: nil)
    }

    private var gatewayStep: EmsStep {
        let title = "VPN gateway"
        if connected {
            return EmsStep(id: .gateway, state: .done, title: title,
                           detail: "Connected.", action: nil, secondary: nil)
        }
        if let r = lastResult, r.message.contains(emsRegistrationRequiredPrefix) {
            return EmsStep(id: .gateway, state: registered ? .todo : .blocked, title: title,
                           detail: registered
                               ? "The last attempt was refused for lack of an EMS registration. This Mac is registered now: connect again."
                               : "The last attempt was refused: the gateway wants this Mac registered with the EMS. Fix the step above, then connect.",
                           action: registered ? .connect : nil, secondary: nil)
        }
        return EmsStep(id: .gateway, state: .waiting, title: title,
                       detail: "Checked when you connect: some gateways admit only registered, compliant Macs.",
                       action: nil, secondary: nil)
    }
}

/// Why an image can't be used for enrollment, and what to do instead.
public enum EnrollmentPackageKind: Equatable, Sendable {
    /// An EMS deployment package (`fctdata`).
    case deployment
    /// FortiClient's online installer: it downloads FortiClient and carries no EMS settings.
    case onlineInstaller
    /// A FortiClient installer without deployment data.
    case plainInstaller
    /// Nothing recognizable.
    case unknown
}

public extension EnrollmentPackageKind {
    /// Classifies a mounted image by its top-level entries.
    static func classify(entries: [String]) -> Self {
        let names = Set(entries.map { $0.lowercased() })
        if names.contains("fctdata") { return .deployment }
        if names.contains("forticlientinstaller.app") { return .onlineInstaller }
        if names.contains("install.mpkg") || names.contains(where: { $0.hasSuffix(".pkg") }) { return .plainInstaller }
        return .unknown
    }

    /// The message for an image that isn't a deployment package.
    var explanation: String? {
        switch self {
        case .deployment:
            return nil
        case .onlineInstaller:
            return "This is FortiClient's online installer. It only downloads FortiClient and carries no EMS settings, so there is nothing to enroll with. You don't need it: open EMS Setup for your profile and register with the EMS address your IT gave you."
        case .plainInstaller:
            return "This FortiClient installer carries no EMS settings. Open EMS Setup for your profile and register with the EMS address your IT gave you, or ask IT for their deployment package."
        case .unknown:
            return "This disk image isn't a FortiClient deployment package."
        }
    }
}

public extension EmsServer {
    /// Whether `other` is this server: same port, and the same name or a shared address.
    /// Resolves names, so call it off the main thread.
    func isSameServer(as other: EmsServer) -> Bool {
        guard port == other.port else { return false }
        if host == other.host { return true }
        let a = Self.addresses(of: host), b = Self.addresses(of: other.host)
        return !a.isDisjoint(with: b)
    }

    private static func addresses(of host: String) -> Set<String> {
        var hints = addrinfo()
        hints.ai_socktype = SOCK_STREAM
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &res) == 0, let first = res else { return [] }
        defer { freeaddrinfo(first) }
        var out = Set<String>()
        var p: UnsafeMutablePointer<addrinfo>? = first
        while let ai = p {
            var buf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(ai.pointee.ai_addr, ai.pointee.ai_addrlen, &buf, socklen_t(buf.count),
                           nil, 0, NI_NUMERICHOST) == 0 {
                out.insert(String(cString: buf))
            }
            p = ai.pointee.ai_next
        }
        return out
    }
}
