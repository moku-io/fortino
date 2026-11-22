// App state: one daemon connection with a subscription, profiles, and actions.

import AppKit
import Foundation
import FortinoKit

/// Progress of bringing the VPN service to this app's build after an update.
enum ServiceUpdate: Equatable {
    /// The service runs an older build and restarts once the VPN is disconnected.
    case afterDisconnect
    /// The service was asked to restart; reconnecting to the new one.
    case restarting
    /// After a restart the service still runs another build: it belongs to another copy of the
    /// app.
    case otherCopy(build: String)
    /// The service predates build IDs and can only be restarted by an administrator.
    case needsAdminRestart
}

@MainActor
final class AppModel: ObservableObject {
    @Published var status: Status?
    @Published var profiles: [Profile] = []
    @Published var storeRevision = 0
    @Published var serviceError: String?
    @Published var actionError: String?
    @Published var selectedProfileId: String?
    /// Profile to show in the editor with the EMS field focused ("Set EMS server").
    @Published var focusEmsFor: String?
    /// The daemon's log level; nil when unknown or a custom `RUST_LOG` filter.
    @Published var logLevel: String?
    /// EMS registration state by `host:port`.
    @Published var emsStatus: [String: EmsStatus] = [:]
    /// Set while the VPN service runs another build than this app.
    @Published var serviceUpdate: ServiceUpdate?

    let socketPath: String
    private var client: DaemonClient?
    private var connecting = false
    private let challenges = ChallengePanelController()
    /// This app's build (`FortinoBuildID`, stamped by bundle.sh). Nil for development runs and
    /// with a development daemon (FORTINO_SOCKET), where there is nothing to compare.
    private let appBuild: String? = ProcessInfo.processInfo.environment["FORTINO_SOCKET"] == nil
        ? Bundle.main.object(forInfoDictionaryKey: "FortinoBuildID") as? String
        : nil
    /// The daemon we asked to restart, so we neither ask it twice nor loop when the restarted
    /// service turns out to be the same build (another copy of the app registered it).
    private var restarted: (instance: String, build: String, at: Date)?
    private var daemon: HelloResult?

    init() {
        socketPath = ProcessInfo.processInfo.environment["FORTINO_SOCKET"]
            ?? UserDefaults.standard.string(forKey: "socketPath")
            ?? defaultSocketPath
        selectedProfileId = UserDefaults.standard.string(forKey: "selectedProfileId")
        challenges.model = self
        Task { await self.connectLoop() }
    }

    var state: SessionState { status?.state ?? .idle }

    var selectedProfile: Profile? {
        profiles.first { $0.id == selectedProfileId } ?? profiles.first
    }

    // MARK: Connection to the daemon

    private func connectLoop() async {
        while true {
            if client == nil && !connecting {
                await openConnection()
            }
            try? await Task.sleep(nanoseconds: 2_000_000_000)
        }
    }

    private func openConnection() async {
        connecting = true
        defer { connecting = false }
        do {
            let c = try DaemonClient(path: socketPath)
            c.onEvent = { [weak self] ev in
                Task { @MainActor in self?.handle(ev) }
            }
            c.onClose = { [weak self, weak c] in
                Task { @MainActor in
                    guard let self, let c, self.client === c else { return }
                    self.client = nil
                    if self.serviceUpdate == .afterDisconnect, let d = self.daemon, let b = d.build {
                        // The older service exited after the disconnect, as asked.
                        self.restarted = (d.daemonInstance, b, Date())
                        self.serviceUpdate = .restarting
                        self.serviceError = nil
                    } else {
                        self.serviceError = "Lost connection to the VPN service. Reconnecting…"
                    }
                }
            }
            let hello = try await c.hello()
            guard await acceptDaemonBuild(c, hello) else { return }
            daemon = hello
            let st = try await c.subscribe()
            client = c
            serviceError = nil
            apply(st)
            logLevel = try? await c.logLevel()
            await refreshProfiles()
        } catch {
            // While the service restarts its socket is briefly missing; say so instead of an
            // error, unless it doesn't come back.
            if serviceUpdate == .restarting, let r = restarted, Date().timeIntervalSince(r.at) < 30 {
                serviceError = nil
                return
            }
            if serviceUpdate == .restarting { serviceUpdate = nil }
            serviceError = (error as? ProtoError)?.message ?? error.localizedDescription
        }
    }

    /// Compares the daemon's build with this app's and asks an older daemon to restart.
    /// Returns false when this connection should be dropped because the daemon is exiting.
    private func acceptDaemonBuild(_ c: DaemonClient, _ h: HelloResult) async -> Bool {
        switch checkDaemonBuild(app: appBuild, daemon: h.build) {
        case .current:
            serviceUpdate = nil
            restarted = nil
            return true
        case .predatesBuildIds:
            serviceUpdate = .needsAdminRestart
            return true
        case .different(let build):
            if let r = restarted {
                if r.instance == h.daemonInstance {
                    // The same process, still finishing its exit.
                    serviceUpdate = .restarting
                    return false
                }
                if r.build == build {
                    serviceUpdate = .otherCopy(build: build)
                    return true
                }
            }
            guard let appBuild else { return true }
            do {
                switch try await c.restartDaemon(build: appBuild) {
                case .now:
                    restarted = (h.daemonInstance, build, Date())
                    serviceUpdate = .restarting
                    serviceError = nil
                    return false
                case .afterDisconnect:
                    serviceUpdate = .afterDisconnect
                    return true
                }
            } catch {
                serviceUpdate = .needsAdminRestart
                return true
            }
        }
    }

    /// Restarts a service that predates build IDs, with an administrator's password.
    func restartServiceAsAdmin(_ service: VPNService) {
        guard state == .idle || state == .recoveryRequired else { return }
        if let e = service.restartAsAdmin() {
            actionError = e
            return
        }
        if let d = daemon {
            restarted = (d.daemonInstance, d.build ?? "", Date())
        }
        serviceUpdate = .restarting
    }

    private func handle(_ ev: Event) {
        switch ev {
        case .status(let s):
            apply(s)
        case .resyncRequired:
            Task { await self.refreshStatus() }
        }
    }

    private func apply(_ s: Status) {
        if let cur = status, cur.daemonInstance == s.daemonInstance, s.seq < cur.seq {
            return
        }
        let changed = status?.state != s.state
        status = s
        challenges.update(status: s)
        // Keepalives run while connected, so the EMS state moves on connect and disconnect.
        if changed && (s.state == .connected || s.state == .idle) {
            Task { await self.refreshEmsStatus() }
        }
    }

    func refreshStatus() async {
        guard let c = client else { return }
        if let s = try? await c.status() { apply(s) }
    }

    func refreshProfiles() async {
        guard let c = client else { return }
        do {
            let l = try await c.profiles()
            profiles = l.profiles
            storeRevision = l.storeRevision
            Task { await self.refreshEmsStatus() }
            if selectedProfileId == nil || !profiles.contains(where: { $0.id == selectedProfileId }) {
                selectedProfileId = profiles.first?.id
            }
        } catch {
            report(error)
        }
    }

    /// Refreshes the EMS state of every profile's EMS server.
    func refreshEmsStatus() async {
        guard let c = client else { return }
        let servers = Set(profiles.compactMap { $0.spec.endpoint.ems })
        for server in servers {
            if let st = try? await c.emsStatus(server: server) {
                emsStatus[server.display] = st
            } else {
                emsStatus[server.display] = nil
            }
        }
    }

    func setLogLevel(_ level: String) {
        Task {
            do {
                try await require().setLogLevel(level)
                logLevel = level
            } catch {
                report(error)
            }
        }
    }

    private func report(_ error: Error) {
        actionError = (error as? ProtoError)?.message ?? error.localizedDescription
    }

    private func require() throws -> DaemonClient {
        guard let c = client else {
            throw ProtoError(code: "service_unavailable", message: serviceError ?? "Not connected to the VPN service")
        }
        return c
    }

    // MARK: Actions

    func select(_ id: String?) {
        selectedProfileId = id
        UserDefaults.standard.set(id, forKey: "selectedProfileId")
    }

    func connect() {
        guard let p = selectedProfile else { return }
        actionError = nil
        Task {
            do {
                let c = try require()
                // Use the latest revision; a stale one is refused by the daemon.
                await refreshProfiles()
                let cur = profiles.first { $0.id == p.id } ?? p
                _ = try await c.connect(ConnectParams(
                    profileId: cur.id, revision: cur.revision,
                    requestKey: UUID().uuidString, username: nil))
            } catch {
                report(error)
            }
        }
    }

    func disconnect() {
        guard let a = status?.attemptId, state.isActive else { return }
        Task {
            do { try await require().disconnect(attempt: a) } catch { report(error) }
        }
    }

    func respond(challenge: Challenge, value: String) async -> ProtoError? {
        guard let a = status?.attemptId else { return nil }
        do {
            try await require().respond(attempt: a, challenge: challenge.id, value: value)
            return nil
        } catch let e as ProtoError {
            return e
        } catch {
            return ProtoError(code: "internal", message: error.localizedDescription)
        }
    }

    func enroll(_ package: EnrollmentPackage) async throws -> EnrollmentReply {
        let r = try await require().enroll(package)
        await refreshEmsStatus()
        return r
    }

    func save(_ spec: ProfileSpec, existing: Profile?) async -> ProtoError? {
        do {
            let c = try require()
            let p: Profile
            if let e = existing {
                p = try await c.update(e.id, revision: e.revision, spec)
            } else {
                p = try await c.create(spec)
            }
            await refreshProfiles()
            select(p.id)
            return nil
        } catch let e as ProtoError {
            return e
        } catch {
            return ProtoError(code: "internal", message: error.localizedDescription)
        }
    }

    func delete(_ p: Profile) async -> ProtoError? {
        do {
            try await require().delete(p.id, revision: p.revision)
            await refreshProfiles()
            return nil
        } catch let e as ProtoError {
            return e
        } catch {
            return ProtoError(code: "internal", message: error.localizedDescription)
        }
    }

    /// Opens the profile window on `id` with the EMS field focused.
    func setEmsServer(for id: String) {
        select(id)
        focusEmsFor = id
    }

    // MARK: Import (parsed by fortino in this user's process)

    var cliPath: String? {
        let candidates = [
            Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/fortino").path,
            ProcessInfo.processInfo.environment["FORTINO_CLI"],
            "/usr/local/bin/fortino",
        ].compactMap { $0 }
        return candidates.first { FileManager.default.isExecutableFile(atPath: $0) }
    }

    func runCLI(_ args: [String]) async -> (Int32, Data, String) {
        guard let path = cliPath else {
            return (127, Data(), "fortino was not found")
        }
        let socket = socketPath
        return await Task.detached {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: path)
            p.arguments = ["--socket", socket, "--json"] + args
            let out = Pipe(), err = Pipe()
            p.standardOutput = out
            p.standardError = err
            p.standardInput = FileHandle.nullDevice
            do { try p.run() } catch { return (127, Data(), error.localizedDescription) }
            let o = out.fileHandleForReading.readDataToEndOfFile()
            let e = err.fileHandleForReading.readDataToEndOfFile()
            p.waitUntilExit()
            return (p.terminationStatus, o, String(decoding: e, as: UTF8.self))
        }.value
    }
}
