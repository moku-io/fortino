// Settings window (⌘,): the VPN service, the command-line tool and troubleshooting. Things used
// rarely live here so the menu-bar panel stays about connecting.

import FortinoKit
import SwiftUI

struct SettingsView: View {
    @ObservedObject var model: AppModel
    @ObservedObject var service: VPNService

    var body: some View {
        // Each tab has its own height, so the window fits it like the system's Settings panes.
        TabView {
            GeneralSettings(model: model, service: service)
                .frame(width: 500, height: 205)
                .tabItem { Label("General", systemImage: "gearshape") }
            CommandLineSettings(model: model, service: service)
                .frame(width: 500, height: 305)
                .tabItem { Label("Command Line", systemImage: "terminal") }
            TroubleshootingSettings(model: model)
                .frame(width: 500, height: 235)
                .tabItem { Label("Troubleshooting", systemImage: "stethoscope") }
        }
    }
}

// MARK: General

struct GeneralSettings: View {
    @ObservedObject var model: AppModel
    @ObservedObject var service: VPNService

    var body: some View {
        Form {
            Section {
                LabeledContent("VPN service") {
                    HStack(spacing: 6) {
                        StatusDot(color: status.color)
                        Text(status.text)
                    }
                }
                if let u = model.serviceUpdate {
                    Text(u.message(state: model.state))
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if service.state == .requiresApproval {
                    LabeledContent {
                        Button("Open Login Items Settings…") { service.openLoginItemsSettings() }
                    } label: {
                        Text("Approval")
                        Text("Allow Fortino in System Settings → General → Login Items.")
                    }
                }
                LabeledContent {
                    Button("Restart…") { model.restartServiceAsAdmin() }
                        .disabled(!canRestart)
                } label: {
                    Text("Restart VPN service")
                    Text(canRestart || !service.isManaged
                         ? "Reloads the service's configuration. Asks for an administrator's password."
                         : "Disconnect first. Asks for an administrator's password.")
                }
                .disabled(!service.isManaged)
            }
            Section {
                LabeledContent("Version") {
                    Text(verbatim: Self.version).textSelection(.enabled)
                }
            }
        }
        .formStyle(.grouped)
        .onAppear { service.refresh() }
    }

    private var canRestart: Bool {
        service.isManaged && service.state == .enabled && ServiceUpdate.canRestart(model.state)
    }

    private var status: (color: Color, text: String) {
        switch service.state {
        case .requiresApproval:
            return (.orange, "Waiting for approval")
        case .failed(let why):
            return (.red, why)
        case .enabled, .external:
            if model.serviceUpdate == .restarting { return (.yellow, "Restarting…") }
            if model.serviceError != nil { return (.orange, "Not responding") }
            if model.serviceUpdate != nil { return (.yellow, "Update pending") }
            return (.green, service.state == .external ? "Running (development)" : "Running")
        }
    }

    static var version: String {
        let info = Bundle.main.infoDictionary ?? [:]
        let v = info["CFBundleShortVersionString"] as? String ?? "development"
        guard let build = info["FortinoBuildID"] as? String else { return v }
        return "\(v) (\(build))"
    }
}

// MARK: Command line

struct CommandLineSettings: View {
    @ObservedObject var model: AppModel
    @ObservedObject var service: VPNService
    @State private var error: String?

    var body: some View {
        Form {
            Section {
                LabeledContent {
                    if service.cliInstalled {
                        Label("Installed", systemImage: "checkmark.circle.fill")
                            .foregroundStyle(.green)
                    } else {
                        Button("Install…") {
                            error = service.installCLI()
                        }
                        .disabled(!service.isManaged)
                    }
                } label: {
                    Text("fortino command")
                    Text(verbatim: VPNService.cliLink)
                }
                if let error {
                    Label(error, systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
            } footer: {
                Text(service.isManaged
                     ? "Links the command to the copy inside Fortino.app, so it updates with the app. Installing asks for an administrator's password."
                     : "Available when Fortino runs from the Applications folder.")
                    .settingsFooter()
            }
            Section("Examples") {
                ForEach(examples, id: \.command) { e in
                    LabeledContent {
                        Text(verbatim: e.command)
                            .font(.system(.callout, design: .monospaced))
                            .textSelection(.enabled)
                    } label: {
                        Text(e.label)
                    }
                }
            }
        }
        .formStyle(.grouped)
        .onAppear { service.refreshCLI() }
    }

    private var examples: [(label: String, command: String)] {
        let name = model.profiles.first.map { Self.quoted($0.spec.name) } ?? "NAME"
        return [
            ("Show the connection", "fortino status"),
            ("Connect", "fortino connect \(name)"),
            ("Disconnect", "fortino disconnect"),
        ]
    }

    /// Quotes a profile name for the shell when it needs it.
    private static func quoted(_ s: String) -> String {
        let plain = s.allSatisfy { $0.isLetter || $0.isNumber || "-_.".contains($0) }
        return plain ? s : "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}

// MARK: Troubleshooting

struct TroubleshootingSettings: View {
    @ObservedObject var model: AppModel
    @State private var logExists = ServiceLog.exists

    var body: some View {
        Form {
            Section {
                Picker("Log level", selection: Binding(
                    get: { model.logLevel ?? "" },
                    set: { model.setLogLevel($0) })
                ) {
                    if model.logLevel == nil { Text("Custom").tag("") }
                    ForEach(LogLevelRow.levels, id: \.self) { Text($0.capitalized).tag($0) }
                }
                .disabled(model.serviceError != nil)
            } footer: {
                Text("Applies to the VPN service until it restarts. Debug and Trace add protocol details such as status codes, cookie names and paths. Passwords, codes and cookie values are never logged.")
                    .settingsFooter()
            }
            Section {
                LabeledContent("Service log") {
                    Text(verbatim: ServiceLog.url.path)
                        .font(.system(.callout, design: .monospaced))
                        .textSelection(.enabled)
                }
                if !logExists {
                    Text(ServiceLog.missingHelp).font(.callout).foregroundStyle(.secondary)
                }
                HStack {
                    Spacer()
                    Button("Show in Finder") { ServiceLog.revealInFinder() }
                    Button("Open in Console") { ServiceLog.openInConsole() }
                }
                .disabled(!logExists)
            }
        }
        .formStyle(.grouped)
        .task {
            logExists = ServiceLog.exists
            await model.refreshLogLevel()
        }
    }
}

extension View {
    /// Secondary footnote under a settings section, aligned with the section's leading edge.
    func settingsFooter() -> some View {
        font(.footnote)
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.leading)
            .frame(maxWidth: .infinity, alignment: .leading)
            .fixedSize(horizontal: false, vertical: true)
    }
}
