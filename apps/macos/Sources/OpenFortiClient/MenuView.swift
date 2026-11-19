// Menu-bar extra: state, profile selection, Connect/Cancel/Disconnect, address and duration.

import OFCKit
import SwiftUI

struct StatusIcon: View {
    let state: SessionState

    var body: some View {
        Image(systemName: symbol)
            .accessibilityLabel("VPN: \(state.label)")
    }

    private var symbol: String {
        switch state {
        case .connected: return "lock.shield.fill"
        case .idle: return "lock.shield"
        case .recoveryRequired: return "exclamationmark.shield"
        case .inUse: return "person.badge.shield.checkmark"
        default: return "shield.lefthalf.filled"
        }
    }
}

func formatDuration(_ secs: Int) -> String {
    let h = secs / 3600, m = (secs / 60) % 60, s = secs % 60
    if h > 0 { return "\(h)h \(m)m" }
    if m > 0 { return "\(m)m \(s)s" }
    return "\(s)s"
}

struct MenuView: View {
    @ObservedObject var model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                StatusIcon(state: model.state).font(.title2)
                VStack(alignment: .leading) {
                    Text(model.state.label).font(.headline)
                    if let n = model.status?.profileName, model.state != .idle {
                        Text(n).font(.subheadline).foregroundStyle(.secondary)
                    }
                }
            }

            if let e = model.serviceError {
                Text(e).foregroundStyle(.red).font(.callout)
            }

            if model.state == .connected, let st = model.status {
                details(st)
            }

            if model.state == .idle || model.state == .recoveryRequired {
                if model.profiles.isEmpty {
                    Text("No profiles yet.").foregroundStyle(.secondary)
                } else {
                    Picker("Profile", selection: Binding(
                        get: { model.selectedProfile?.id ?? "" },
                        set: { model.select($0) })) {
                        ForEach(model.profiles) { p in
                            Text(p.spec.name).tag(p.id)
                        }
                    }
                    if let p = model.selectedProfile {
                        Text(verbatim: "\(p.spec.endpoint.host):\(String(p.spec.endpoint.port)) · \(p.spec.ipPolicy.label)")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                if let r = model.status?.lastResult, let code = r.code {
                    Text("Last attempt: \(r.message)")
                        .font(.caption)
                        .foregroundStyle(code == "cancelled" ? Color.secondary : Color.red)
                }
            }

            if let e = model.actionError {
                Text(e).foregroundStyle(.red).font(.callout)
            }

            primaryButton

            Divider()
            Button("Profiles…") {
                openWindow(id: "profiles")
                NSApp.activate(ignoringOtherApps: true)
            }
            Button("Import…") {
                openWindow(id: "import")
                NSApp.activate(ignoringOtherApps: true)
            }
            Divider()
            Button("Quit OpenFortiClient") { NSApp.terminate(nil) }
                .help("Quitting leaves the VPN connected")
        }
        .padding(14)
        .frame(width: 300)
        .task { await model.refreshProfiles() }
    }

    @ViewBuilder private func details(_ st: Status) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            if let ip = st.assignedIp { Text("Address: \(ip)") }
            if let i = st.interface { Text("Interface: \(i)") }
            if let p = st.ipPolicy { Text(p.label) }
            if let since = st.connectedSince {
                TimelineView(.periodic(from: .now, by: 1)) { ctx in
                    let secs = max(0, Int(ctx.date.timeIntervalSince1970) - since)
                    Text("Connected for \(formatDuration(secs))")
                }
            }
        }
        .font(.callout)
    }

    @ViewBuilder private var primaryButton: some View {
        switch model.state {
        case .connected:
            Button("Disconnect") { model.disconnect() }.keyboardShortcut(.defaultAction)
        case .starting, .authenticating, .awaitingInput, .configuring:
            Button("Cancel") { model.disconnect() }
        case .stopping:
            Button("Disconnecting…") {}.disabled(true)
        case .inUse:
            Text("Another user is connected.").foregroundStyle(.secondary)
        case .idle, .recoveryRequired:
            Button("Connect") { model.connect() }
                .keyboardShortcut(.defaultAction)
                .disabled(model.selectedProfile == nil || model.serviceError != nil)
        }
    }
}
