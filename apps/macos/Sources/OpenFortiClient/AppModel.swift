// App state: one daemon connection with a subscription, profiles, and actions.

import AppKit
import Foundation
import OFCKit

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

    let socketPath: String
    private var client: DaemonClient?
    private var connecting = false
    private let challenges = ChallengePanelController()

    init() {
        socketPath = ProcessInfo.processInfo.environment["OFC_SOCKET"]
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
                    self.serviceError = "Lost connection to the VPN service. Reconnecting…"
                }
            }
            _ = try await c.hello()
            let st = try await c.subscribe()
            client = c
            serviceError = nil
            apply(st)
            await refreshProfiles()
        } catch let e as ProtoError {
            serviceError = e.message
        } catch {
            serviceError = error.localizedDescription
        }
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
        status = s
        challenges.update(status: s)
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
            if selectedProfileId == nil || !profiles.contains(where: { $0.id == selectedProfileId }) {
                selectedProfileId = profiles.first?.id
            }
        } catch {
            report(error)
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

    // MARK: Import (parsed by ofctl in this user's process)

    var ofctlPath: String? {
        let candidates = [
            Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS/ofctl").path,
            ProcessInfo.processInfo.environment["OFCTL"],
            "/usr/local/bin/ofctl",
        ].compactMap { $0 }
        return candidates.first { FileManager.default.isExecutableFile(atPath: $0) }
    }

    func runOfctl(_ args: [String]) async -> (Int32, Data, String) {
        guard let path = ofctlPath else {
            return (127, Data(), "ofctl was not found")
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
