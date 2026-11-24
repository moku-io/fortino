// Guided EMS setup for one profile: the chain from EMS server to gateway, where it breaks, and
// the one action that moves it on. The steps themselves come from FortinoKit's EmsSetupInput.

import AppKit
import FortinoKit
import SwiftUI

struct EmsSetupWindow: View {
    @ObservedObject var model: AppModel
    @Environment(\.openWindow) private var openWindow
    @State private var serverCheck: EmsServerCheck = .checking
    @State private var checkRun = 0
    @State private var busy = false
    @State private var message: String?
    @State private var messageIsError = false

    private var profile: Profile? { model.emsSetupProfile }

    var body: some View {
        VStack(spacing: 0) {
            ServiceUpdateBanner(model: model)
            // The roadblock card can be tall; the checklist below it must stay reachable.
            ScrollView { steps.padding(20) }
        }
        .frame(minWidth: 520, idealWidth: 560, minHeight: 460, alignment: .topLeading)
        .disabled(busy)
    }

    private var steps: some View {
        VStack(alignment: .leading, spacing: 16) {
            if let profile, let server = profile.spec.endpoint.ems {
                content(profile, server)
                    .task(id: "\(server.display)#\(checkRun)") { await check(server) }
                    .task(id: watching(server)) {
                        // While a blocked step waits on something outside Fortino (FortiClient,
                        // IT), re-read the state so the tick appears without a click.
                        guard watching(server) else { return }
                        while !Task.isCancelled {
                            try? await Task.sleep(nanoseconds: 3_000_000_000)
                            await model.refreshEmsStatus()
                        }
                    }
            } else if let profile {
                noEms(profile)
            } else {
                Text("Add a VPN profile first.").foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
    }

    // MARK: Layout

    @ViewBuilder
    private func content(_ profile: Profile, _ server: EmsServer) -> some View {
        let input = input(profile, server)

        VStack(alignment: .leading, spacing: 4) {
            Text("EMS Setup for “\(profile.spec.name)”").font(.title2.weight(.semibold))
            Text("Some VPN gateways only admit Macs registered with their organization's EMS. Follow the steps from the top; each one says what it does.")
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }

        if let block = input.roadblock {
            RoadblockCard(step: block) { perform($0, profile: profile, server: server) }
        } else if input.steps.allSatisfy({ $0.state == .done || $0.state == .waiting }) {
            Label("Nothing to do. Connect when you're ready.", systemImage: "checkmark.seal.fill")
                .foregroundStyle(.green)
        }

        VStack(alignment: .leading, spacing: 0) {
            ForEach(Array(input.steps.enumerated()), id: \.element.id) { index, step in
                StepRow(step: step, isLast: index == input.steps.count - 1,
                        isRoadblock: step.id == input.roadblock?.id) {
                    perform($0, profile: profile, server: server)
                }
            }
        }

        if busy { ProgressView().controlSize(.small) }
        if let message {
            Text(message)
                .foregroundStyle(messageIsError ? .red : .secondary)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }

        HStack {
            Button("Copy Details for IT") { copyDetails(input, profile: profile) }
                .help("Copies each step's state, so you can send it to your IT administrator")
            Spacer()
            Button("Check Again") { refresh() }
        }
    }

    private func noEms(_ profile: Profile) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("EMS Setup for “\(profile.spec.name)”").font(.title2.weight(.semibold))
            Text("This profile names no EMS server. If your IT gave you an EMS address (a host name and a port, for example 8013 or 9016), add it to the profile; Fortino then registers this Mac with it.")
                .fixedSize(horizontal: false, vertical: true)
            Button("Add EMS Server…") {
                model.setEmsServer(for: profile.id)
                openWindow(id: "profiles")
            }
        }
    }

    private func input(_ profile: Profile, _ server: EmsServer) -> EmsSetupInput {
        EmsSetupInput(
            server: server,
            serverCheck: serverCheck,
            status: model.emsStatus[server.display],
            lastResult: model.status?.profileId == profile.id ? model.status?.lastResult : nil,
            connected: model.status?.profileId == profile.id && model.state == .connected)
    }

    private func watching(_ server: EmsServer) -> Bool {
        guard let profile else { return false }
        return input(profile, server).roadblock?.watches == true
    }

    // MARK: Actions

    private func perform(_ action: EmsAction, profile: Profile, server: EmsServer) {
        message = nil
        switch action {
        case .checkAgain:
            refresh()
        case .editProfile:
            model.setEmsServer(for: profile.id)
            openWindow(id: "profiles")
        case .enrollWithPackage:
            model.emsSetupProfileId = profile.id
            openWindow(id: "enrollment")
        case .connect:
            model.select(profile.id)
            model.connect()
        case .openFortiClient:
            openFortiClient()
        case .uninstallFortiClient:
            uninstallFortiClient()
        case .copyDetails:
            copyDetails(input(profile, server), profile: profile)
        case .approve:
            run {
                if try await model.approveWithCertificateCheck(server) {
                    await model.refreshEmsStatus()
                    return "Allowed. Next: register this Mac."
                }
                return nil
            }
        case .registerNow:
            run {
                let r = try await model.registerEms(server)
                switch r.status {
                case "registered":
                    return r.rules
                        ? "Registered, and the EMS sent its compliance rules."
                        : "Registered. The EMS hasn't sent compliance rules yet; they usually arrive with the first check-in."
                case "managed-by-forticlient":
                    return "FortiClient already manages this Mac on this EMS; Fortino uses that registration."
                case "held-by-forticlient":
                    return "Not registered: FortiClient holds this Mac's registration with this EMS. See the step above."
                case "approval-required":
                    return "This server needs to be allowed on this Mac first."
                default:
                    return "The service answered “\(r.status)”."
                }
            }
        }
    }

    /// Runs an action, showing its outcome or its error under the steps.
    private func run(_ body: @escaping () async throws -> String?) {
        busy = true
        Task {
            defer { busy = false }
            do {
                message = try await body()
                messageIsError = false
            } catch {
                message = (error as? ProtoError)?.message ?? error.localizedDescription
                messageIsError = true
            }
        }
    }

    private func refresh() {
        checkRun += 1
        Task { await model.refreshEmsStatus() }
    }

    private func check(_ server: EmsServer) async {
        serverCheck = .checking
        await model.refreshEmsStatus()
        do {
            let cert = try await ServerCertificate.fetch(server)
            serverCheck = .reachable(trusted: cert.trusted)
        } catch {
            serverCheck = .unreachable((error as? ProtoError)?.message ?? error.localizedDescription)
        }
    }

    private func openFortiClient() {
        let app = URL(fileURLWithPath: "/Applications/FortiClient.app")
        guard FileManager.default.fileExists(atPath: app.path) else {
            message = "FortiClient isn't in Applications. If it's installed elsewhere, open it from there."
            messageIsError = true
            return
        }
        NSWorkspace.shared.openApplication(at: app, configuration: .init())
        message = "In FortiClient, open Zero Trust Telemetry and click Disconnect. This window updates by itself."
        messageIsError = false
    }

    private func uninstallFortiClient() {
        let uninstaller = URL(fileURLWithPath: "/Applications/FortiClientUninstaller.app")
        let alert = NSAlert()
        alert.messageText = "Uninstall FortiClient?"
        alert.informativeText = "FortiClient's uninstaller removes FortiClient and its VPN profiles from this Mac, and asks for an administrator password. To keep the profiles, first choose File > Import from FortiClient in Fortino."
        alert.addButton(withTitle: "Open Uninstaller")
        alert.addButton(withTitle: "Import Profiles First")
        alert.addButton(withTitle: "Cancel")
        switch alert.runModal() {
        case .alertFirstButtonReturn:
            if FileManager.default.fileExists(atPath: uninstaller.path) {
                NSWorkspace.shared.openApplication(at: uninstaller, configuration: .init())
                message = "Follow FortiClient's uninstaller. This window updates by itself when it's done."
                messageIsError = false
            } else {
                message = "FortiClient's uninstaller isn't in Applications. Use the Uninstall item in FortiClient's disk image, or ask your IT administrator."
                messageIsError = true
            }
        case .alertSecondButtonReturn:
            openWindow(id: "import")
        default:
            break
        }
    }

    private func copyDetails(_ input: EmsSetupInput, profile: Profile) {
        var lines = ["Fortino EMS Setup", "Profile: \(profile.spec.name)",
                     "Gateway: \(profile.spec.endpoint.host):\(profile.spec.endpoint.port)",
                     "EMS: \(input.server.display)",
                     "EMS state: \(input.status?.state ?? "unknown")"]
        for s in input.steps {
            lines.append("- \(s.title): \(Self.word(s.state)). \(s.detail)")
        }
        if let r = input.lastResult { lines.append("Last attempt: \(r.message)") }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(lines.joined(separator: "\n"), forType: .string)
        message = "Copied."
        messageIsError = false
    }

    static func word(_ s: EmsStepState) -> String {
        switch s {
        case .done: return "done"
        case .waiting: return "waiting"
        case .checking: return "checking"
        case .todo: return "to do"
        case .blocked: return "blocked"
        case .warning: return "warning"
        }
    }
}

// MARK: Pieces

extension EmsAction {
    var title: String {
        switch self {
        case .checkAgain: return "Check Again"
        case .editProfile: return "Edit EMS Address…"
        case .approve: return "Allow on This Mac…"
        case .registerNow: return "Register Now"
        case .enrollWithPackage: return "Use a Deployment Package…"
        case .connect: return "Connect"
        case .openFortiClient: return "Open FortiClient"
        case .uninstallFortiClient: return "Uninstall FortiClient…"
        case .copyDetails: return "Copy Details for IT"
        }
    }
}

private struct StateIcon: View {
    let state: EmsStepState

    var body: some View {
        Group {
            switch state {
            case .done: Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
            case .todo: Image(systemName: "arrow.right.circle.fill").foregroundStyle(Color.accentColor)
            case .blocked: Image(systemName: "xmark.octagon.fill").foregroundStyle(.red)
            case .warning: Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
            case .waiting: Image(systemName: "circle").foregroundStyle(.tertiary)
            case .checking: ProgressView().controlSize(.mini)
            }
        }
        .font(.title3)
        .frame(width: 22, height: 22)
        .accessibilityLabel(EmsSetupWindow.word(state))
    }
}

/// One link in the chain, with a line down to the next.
private struct StepRow: View {
    let step: EmsStep
    let isLast: Bool
    let isRoadblock: Bool
    let perform: (EmsAction) -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            VStack(spacing: 2) {
                StateIcon(state: step.state)
                if !isLast {
                    Rectangle().fill(.quaternary).frame(width: 2).frame(maxHeight: .infinity)
                }
            }
            VStack(alignment: .leading, spacing: 3) {
                Text(step.title)
                    .fontWeight(.medium)
                    .foregroundStyle(step.state == .waiting ? .secondary : .primary)
                // The roadblock card above already carries this step's text and actions.
                if !isRoadblock {
                    Text(step.detail)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    if step.state == .warning, let a = step.action {
                        Button(a.title) { perform(a) }.controlSize(.small)
                    }
                } else {
                    Text("See above").font(.callout).foregroundStyle(.secondary)
                }
            }
            .padding(.bottom, isLast ? 0 : 14)
            Spacer(minLength: 0)
        }
    }
}

/// One numbered way out of a blocked step.
private struct FixOption: View {
    let number: Int
    let fix: EmsFix
    let perform: (EmsAction) -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Text("\(number)")
                .font(.callout.weight(.semibold).monospacedDigit())
                .frame(width: 22, height: 22)
                .background(Circle().fill(Color.secondary.opacity(0.18)))
            VStack(alignment: .leading, spacing: 4) {
                Text(fix.title).fontWeight(.semibold)
                Text(fix.detail)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if let a = fix.action {
                    Button(a.title) { perform(a) }
                        .buttonStyle(.borderedProminent)
                        .padding(.top, 2)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(10)
        .background(RoundedRectangle(cornerRadius: 6).fill(Color(nsColor: .controlBackgroundColor)))
    }
}

/// The first step that needs the user, with its explanation and actions.
private struct RoadblockCard: View {
    let step: EmsStep
    let perform: (EmsAction) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                StateIcon(state: step.state)
                Text(step.state == .blocked ? "Blocked: \(step.title)" : "Next: \(step.title)")
                    .font(.headline)
            }
            Text(step.detail)
                .fixedSize(horizontal: false, vertical: true)
                .textSelection(.enabled)
            ForEach(Array(step.fixes.enumerated()), id: \.offset) { index, fix in
                FixOption(number: index + 1, fix: fix, perform: perform)
            }
            if step.watches {
                HStack(spacing: 6) {
                    ProgressView().controlSize(.mini)
                    Text("Fortino checks again every few seconds; this updates by itself.")
                        .font(.callout).foregroundStyle(.secondary)
                }
            }
            HStack {
                if let a = step.action {
                    Button(a.title) { perform(a) }
                        .buttonStyle(.borderedProminent)
                        .keyboardShortcut(.defaultAction)
                }
                if let b = step.secondary {
                    Button(b.title) { perform(b) }
                }
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 8).fill(
            step.state == .blocked ? Color.red.opacity(0.08) : Color.accentColor.opacity(0.08)))
        .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(
            step.state == .blocked ? Color.red.opacity(0.35) : Color.accentColor.opacity(0.35)))
    }
}
