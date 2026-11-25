// App state: one daemon connection with a subscription, profiles, and actions.

import AppKit
import Foundation
import UniformTypeIdentifiers
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
    /// File → New Profile: the Profiles window opens the new-profile form and clears this.
    @Published var newProfileRequested = false
    /// The daemon's log level; nil when unknown or a custom `RUST_LOG` filter.
    @Published var logLevel: String?
    /// EMS registration state by `host:port`.
    @Published var emsStatus: [String: EmsStatus] = [:]
    /// Set while the VPN service runs another build than this app.
    @Published var serviceUpdate: ServiceUpdate?
    /// The failed attempt whose EMS certificate the user has since approved, so the row stops
    /// offering the review until a new attempt fails.
    @Published var reviewedEmsFailure: String?
    /// The failed attempt whose gateway certificate the user has since trusted.
    @Published var reviewedGatewayFailure: String?
    /// The profile the EMS Setup and enrollment windows work on.
    @Published var emsSetupProfileId: String?
    /// What the login keychain holds for each profile that saves its password, by profile ID.
    @Published var savedPasswords: [String: SavedPasswordState] = [:]
    /// The username typed for an attempt, so its password is saved for the right account.
    var typedUsername: (attempt: String, value: String)?
    /// A typed password to save once its attempt connects. See SavedPasswords.swift.
    var pendingPasswordSave: PendingPasswordSave?
    /// The attempt whose password prompt the keychain answered.
    @Published var keychainAnsweredAttempt: String?
    /// The last attempt this app started. Only its password prompt is answered from the
    /// keychain: an attempt started elsewhere (`fortino connect --username …`) may sign in as
    /// another account, and the command that started it handles its own saved password.
    var ownAttempt: String?

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
        var ticks = 0
        while true {
            if client == nil && !connecting {
                await openConnection()
            }
            // Keepalives start a few seconds after connecting and repeat while connected, so
            // the EMS state read on the state change is soon out of date: refresh it every 30 s.
            ticks += 1
            if ticks % 15 == 0 && state == .connected {
                await refreshEmsStatus()
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
            // Development aid: FORTINO_DEBUG_SERVICE_UPDATE=after-disconnect shows the
            // service-update banner without a second build, for layout checks and screenshots.
            serviceUpdate = ProcessInfo.processInfo.environment["FORTINO_DEBUG_SERVICE_UPDATE"]
                == "after-disconnect" ? .afterDisconnect : nil
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
    func restartServiceAsAdmin() {
        guard ServiceUpdate.canRestart(state) else { return }
        if let e = VPNService.restartAsAdmin() {
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
        settlePendingPassword(s)
        challenges.update(status: s)
        // Keepalives run while connected, so the EMS state moves on connect and disconnect.
        if changed && (s.state == .connected || s.state == .idle) {
            Task { await self.refreshEmsStatus() }
            // An attempt may have saved a password or marked a saved one refused.
            if let p = profiles.first(where: { $0.id == s.profileId && $0.spec.savePassword == true }) {
                Task { await self.refreshSavedPassword(p.id) }
            }
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

    /// Re-reads the level, which `fortino log-level` may have changed.
    func refreshLogLevel() async {
        guard let c = client else { return }
        logLevel = try? await c.logLevel()
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

    /// Unsaved changes in the profile window's editor. `ProfileEditor` registers them while its
    /// form differs from the stored profile; `save` returns an error message, or nil once saved.
    struct PendingEdits {
        let editor: UUID
        let profileId: String
        let save: () async -> String?
    }

    /// Not published: nothing renders from it, and editors update it during view updates.
    var pendingEdits: PendingEdits?

    /// Connects the selected profile. With `savingEdits` (the profile window's Connect button),
    /// unsaved changes shown in the editor are saved first, so Connect uses what the user sees.
    func connect(savingEdits: Bool = false) {
        guard let p = selectedProfile else { return }
        actionError = nil
        let pending = savingEdits ? pendingEdits.flatMap { $0.profileId == p.id ? $0 : nil } : nil
        Task {
            if let pending, let e = await pending.save() {
                actionError = e
                return
            }
            do {
                let c = try require()
                // Use the latest revision; a stale one is refused by the daemon.
                await refreshProfiles()
                let cur = profiles.first { $0.id == p.id } ?? p
                guard try await approveEmsBeforeConnecting(cur, client: c) else { return }
                let r = try await c.connect(ConnectParams(
                    profileId: cur.id, revision: cur.revision,
                    requestKey: UUID().uuidString, username: nil))
                ownAttempt = r.attemptId
            } catch {
                report(error)
            }
        }
    }

    /// The service connects without the EMS when the profile's EMS server isn't approved on this
    /// Mac (it can't ask for an administrator password itself), so the app asks first. False
    /// when the user cancelled; true to connect, with or without the EMS.
    private func approveEmsBeforeConnecting(_ profile: Profile, client c: DaemonClient) async throws -> Bool {
        guard let server = profile.spec.endpoint.ems,
              let st = try? await c.emsStatus(server: server) else { return true }
        emsStatus[server.display] = st
        guard st.state == "unconfigured" else { return true }

        let alert = NSAlert()
        alert.messageText = "Approve the EMS server \(server.display)?"
        alert.informativeText = """
        \(profile.spec.name) uses this EMS server, which hasn't been approved on this Mac. \
        Approving lets Fortino register this Mac with it when you connect, and needs an \
        administrator password.

        Without it, Fortino connects without the EMS, and the gateway may refuse the \
        connection or limit access.
        """
        alert.addButton(withTitle: "Approve…")
        alert.addButton(withTitle: "Cancel")
        alert.addButton(withTitle: "Connect Without EMS")
        NSApp.activate(ignoringOtherApps: true)
        switch alert.runModal() {
        case .alertFirstButtonReturn:
            guard try await approveWithCertificateCheck(server) else { return false }
            await refreshEmsStatus()
            return true
        case .alertThirdButtonReturn:
            return true
        default:
            return false
        }
    }

    /// Brings the sign-in panel back after the user closed it while the prompt is still open.
    func showSignIn() {
        challenges.reopen()
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

    /// Approves an EMS server on this Mac (administrator password), so connecting registers
    /// with it. No deployment package needed for a Mac the EMS already knows.
    func approveEms(_ server: EmsServer) {
        actionError = nil
        let failed = status?.lastResult?.attemptId
        Task {
            do {
                if try await approveWithCertificateCheck(server, afterFailure: true) {
                    reviewedEmsFailure = failed
                    await refreshEmsStatus()
                }
            } catch {
                report(error)
            }
        }
    }

    /// The profile whose last attempt failed on the gateway certificate and hasn't been
    /// reviewed since; nil otherwise.
    var gatewayTrustFailure: Profile? {
        guard state == .idle, let st = status, let r = st.lastResult, r.code == "trust_failure",
              r.message.hasPrefix("gateway certificate"), r.attemptId != reviewedGatewayFailure
        else { return nil }
        return profiles.first { $0.id == st.profileId }
    }

    /// Shows the gateway's certificate and, if the user trusts it, pins it on this Mac
    /// (administrator password). Connecting again then trusts exactly that certificate.
    func reviewGatewayCertificate(_ profile: Profile) {
        actionError = nil
        let failed = status?.lastResult?.attemptId
        let endpoint = profile.spec.endpoint
        Task {
            do {
                let cert = try await ServerCertificate.fetch(
                    host: endpoint.host, port: endpoint.port, kind: "VPN gateway")
                // macOS may trust a chain Fortino's CA bundle can't complete; say so instead.
                let reason = cert.trusted
                    ? "macOS trusts this certificate, but Fortino could not verify it against its CA bundle."
                    : nil
                guard cert.confirmTrust(kind: "VPN gateway", server: "\(endpoint.host):\(endpoint.port)",
                                        reason: reason) else { return }
                try GatewayPin(endpoint: endpoint).write(pin: cert.sha256)
                reviewedGatewayFailure = failed
            } catch {
                report(error)
            }
        }
    }

    /// Checks the server's certificate, warns once if macOS doesn't trust it, and writes the
    /// approval (pinning the certificate the user accepted). False when the user cancelled.
    /// `afterFailure`: the service has just failed to verify this certificate, so it is pinned
    /// even when macOS trusts it. The service checks against its own CA bundle, which lacks
    /// roots that only the keychain has (one installed by device management, for example);
    /// approving without a pin would fail the same way again.
    func approveWithCertificateCheck(_ server: EmsServer, afterFailure: Bool = false) async throws -> Bool {
        let cert = try await ServerCertificate.fetch(server)
        var pin: String?
        if !cert.trusted || afterFailure {
            let reason = cert.trusted
                ? "macOS trusts this certificate, but Fortino could not verify it against its CA bundle."
                : nil
            guard cert.confirmTrust(kind: "EMS server", server: server.display, reason: reason) else {
                return false
            }
            pin = cert.sha256
        }
        try EnrollmentApproval(server: server).requestInApp(pin: pin)
        return true
    }

    /// The profile for the EMS Setup and enrollment windows: the one they were opened for,
    /// else the selected one.
    var emsSetupProfile: Profile? {
        profiles.first { $0.id == emsSetupProfileId } ?? selectedProfile
    }

    /// Registers this Mac with `server` now, without a deployment package.
    func registerEms(_ server: EmsServer) async throws -> EnrollmentReply {
        let r = try await require().register(server: server)
        await refreshEmsStatus()
        return r
    }

    /// Whether the last attempt was `profile`'s and failed for lack of an EMS registration.
    func lastAttemptNeedsEms(_ profile: Profile) -> Bool {
        guard state == .idle, status?.profileId == profile.id,
              let r = status?.lastResult else { return false }
        return r.message.contains(emsRegistrationRequiredPrefix)
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
                if e.spec.savePassword == true && spec.savePassword != true {
                    await forgetSavedPassword(e.id)
                }
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
            // Also with the option off: a password can be saved without it.
            _ = await runCLI(["password", "forget", p.id])
            savedPasswords[p.id] = nil
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

    // MARK: Export (written by fortino in this user's process)

    /// Saves every profile as a FortiClient XML configuration. No usernames or passwords are
    /// written; Fortino-only settings (EMS server, DNS, IP policy) have no FortiClient equivalent.
    func exportProfiles() async {
        let panel = NSSavePanel()
        panel.title = "Export to FortiClient"
        panel.message = "FortiClient can restore this file. Usernames and passwords are not included."
        panel.nameFieldStringValue = "Fortino Profiles.xml"
        panel.allowedContentTypes = [.xml]
        NSApp.activate(ignoringOtherApps: true)
        guard panel.runModal() == .OK, let url = panel.url else { return }
        let (code, out, err) = await runCLI(["profile", "export", "--output", url.path])
        guard code != 0 else { return }
        let alert = NSAlert()
        alert.messageText = "Export failed."
        alert.informativeText = cliFailure(stdout: out, stderr: err) ?? ""
        alert.runModal()
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

    /// Runs the bundled `fortino` in this user's session. `input` becomes its standard input
    /// (a password to save), so it never appears in the arguments.
    func runCLI(_ args: [String], input: Data? = nil) async -> (Int32, Data, String) {
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
            let stdin = input.map { _ in Pipe() }
            p.standardInput = stdin ?? FileHandle.nullDevice
            do { try p.run() } catch { return (127, Data(), error.localizedDescription) }
            if let stdin, let input {
                stdin.fileHandleForWriting.write(input)
                try? stdin.fileHandleForWriting.close()
            }
            let o = out.fileHandleForReading.readDataToEndOfFile()
            let e = err.fileHandleForReading.readDataToEndOfFile()
            p.waitUntilExit()
            return (p.terminationStatus, o, String(decoding: e, as: UTF8.self))
        }.value
    }
}
