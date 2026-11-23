// Menu-bar extra, laid out like the system's Wi-Fi/VPN menus in Control Center: a header,
// one row per VPN profile with a switch, then menu-style actions. Only standard controls, so
// macOS supplies the material (Liquid Glass on macOS 26, vibrancy before).

import FortinoKit
import SwiftUI

extension SessionState {
    var menuBarSymbol: String {
        switch self {
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

/// Connection details for the active attempt, e.g. "10.212.134.200 · 4m 12s".
struct ConnectionSummary: View {
    let status: Status

    var body: some View {
        switch status.state {
        case .connected:
            TimelineView(.periodic(from: .now, by: 1)) { ctx in
                Text(verbatim: detail(now: ctx.date))
            }
        case .awaitingInput:
            Text("Waiting for sign-in")
        default:
            Text(status.state.label)
        }
    }

    private func detail(now: Date) -> String {
        var parts: [String] = []
        if let ip = status.assignedIp { parts.append(ip) }
        if let since = status.connectedSince {
            parts.append(formatDuration(max(0, Int(now.timeIntervalSince1970) - since)))
        }
        return parts.joined(separator: " · ")
    }
}

struct MenuView: View {
    @ObservedObject var model: AppModel
    @ObservedObject var service: VPNService
    @ObservedObject private var optionKey = OptionKey.shared
    @Environment(\.openWindow) private var openWindow
    @State private var host = WindowRef()

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            header
            if service.state == .requiresApproval {
                notice("Allow Fortino's VPN service in System Settings to connect.",
                       symbol: "lock.shield", tint: .orange)
                MenuRow(title: "Open Login Items Settings…") {
                    closePanel()
                    service.openLoginItemsSettings()
                }
            } else if case .failed(let why) = service.state {
                notice(why, symbol: "exclamationmark.triangle.fill", tint: .orange)
            } else if let u = model.serviceUpdate, u != .afterDisconnect || model.serviceError == nil {
                serviceUpdateNotice(u)
            } else if let e = model.serviceError {
                notice(e, symbol: "exclamationmark.triangle.fill", tint: .orange)
            } else if model.state == .inUse {
                notice("Another user on this Mac is connected.", symbol: "person.fill", tint: .secondary)
            } else if model.state == .recoveryRequired {
                notice("Network settings from the last session could not be restored. Connecting retries the cleanup.",
                       symbol: "exclamationmark.shield.fill", tint: .orange)
            }

            if !model.profiles.isEmpty {
                Divider().padding(.vertical, 2)
                Text("Profiles").font(.subheadline.weight(.semibold)).foregroundStyle(.secondary)
                    .padding(.horizontal, 8)
                ForEach(model.profiles) { p in
                    ProfileRow(model: model, profile: p)
                }
            }

            if let e = model.actionError {
                notice(e, symbol: "xmark.octagon.fill", tint: .red)
            } else if model.state == .idle, let r = model.status?.lastResult,
                      let code = r.code, code != "cancelled" {
                notice("Last attempt: \(r.message)", symbol: "exclamationmark.circle", tint: .secondary)
            }

            Divider().padding(.vertical, 2)
            MenuRow(title: model.profiles.isEmpty ? "Add a VPN Profile…" : "Open Fortino…") {
                closePanel()
                if model.profiles.isEmpty { model.newProfileRequested = true }
                openWindow(id: "profiles")
                NSApp.activate(ignoringOtherApps: true)
            }
            if model.profiles.isEmpty {
                // First run: importing is the usual way in for someone coming from FortiClient.
                MenuRow(title: "Import from FortiClient…") {
                    closePanel()
                    openWindow(id: "import")
                    NSApp.activate(ignoringOtherApps: true)
                }
            }
            SettingsRow(willOpen: closePanel)
            if optionKey.isDown {
                // Troubleshooting, shown while Option is held (like the system's Wi-Fi menu).
                Divider().padding(.vertical, 2)
                LogLevelRow(model: model)
                MenuRow(title: "Open Service Log in Console") {
                    closePanel()
                    ServiceLog.openInConsole()
                }
                .disabled(!ServiceLog.exists)
                MenuRow(title: "Show Service Log in Finder") {
                    closePanel()
                    ServiceLog.revealInFinder()
                }
                .disabled(!ServiceLog.exists)
            }
            Divider().padding(.vertical, 2)
            MenuRow(title: "Quit Fortino", help: "The VPN stays connected after quitting") {
                NSApp.terminate(nil)
            }
        }
        .padding(8)
        .frame(width: 300)
        .background(WindowReader(ref: host))
        .task {
            service.refresh()
            service.refreshCLI()
            await model.refreshProfiles()
        }
    }

    /// Closes the menu-bar panel before an action that opens a window or another app; SwiftUI
    /// leaves it open otherwise. Not the Menu Preview window, which shows the same view.
    /// It toggles through the status item, as a click on the icon does: closing the window
    /// directly leaves SwiftUI thinking the panel is open, and the next click is lost.
    private func closePanel() {
        guard let w = host.window, w.level == .popUpMenu, w.isVisible else { return }
        if let button = Self.statusButton() {
            button.performClick(nil)
        } else {
            w.close()
        }
    }

    private static func statusButton() -> NSStatusBarButton? {
        func find(_ v: NSView?) -> NSStatusBarButton? {
            guard let v else { return nil }
            if let b = v as? NSStatusBarButton { return b }
            return v.subviews.lazy.compactMap(find).first
        }
        for w in NSApp.windows where w.className.contains("StatusBarWindow") {
            if let b = find(w.contentView?.superview ?? w.contentView) { return b }
        }
        return nil
    }

    @ViewBuilder
    private func serviceUpdateNotice(_ u: ServiceUpdate) -> some View {
        notice(u.message(state: model.state), symbol: u.symbol, tint: u.tint)
        if u.offersRestart(state: model.state) {
            MenuRow(title: "Restart VPN Service…", help: "Asks for an administrator's password") {
                closePanel()
                model.restartServiceAsAdmin()
            }
        }
    }

    private var header: some View {
        HStack(spacing: 10) {
            Text("VPN").font(.headline)
            Spacer()
            if model.state.isActive && model.state != .connected {
                ProgressView().controlSize(.small)
            }
            Text(model.state.label).foregroundStyle(.secondary)
        }
        .padding(.horizontal, 8)
        .padding(.top, 4)
    }

    private func notice(_ text: String, symbol: String, tint: Color) -> some View {
        Label {
            Text(text).fixedSize(horizontal: false, vertical: true)
        } icon: {
            Image(systemName: symbol).foregroundStyle(tint)
        }
        .font(.callout)
        .padding(.horizontal, 8)
    }
}

/// One profile with a switch, like a VPN configuration in Control Center.
struct ProfileRow: View {
    @ObservedObject var model: AppModel
    let profile: Profile

    private var isCurrent: Bool { model.status?.profileId == profile.id && model.state.isActive }

    private var isOn: Binding<Bool> {
        Binding(
            get: { isCurrent },
            set: { on in
                if on {
                    model.select(profile.id)
                    model.connect()
                } else {
                    model.disconnect()
                }
            })
    }

    /// Another attempt (ours or another user's) holds the single VPN slot.
    private var blocked: Bool {
        (model.state.isActive && !isCurrent) || model.state == .inUse || model.state == .stopping
            || model.serviceError != nil
    }

    var body: some View {
        HStack(spacing: 10) {
            ZStack {
                Circle().fill(isCurrent && model.state == .connected ? Color.accentColor : Color.secondary.opacity(0.2))
                Image(systemName: "network.badge.shield.half.filled")
                    .foregroundStyle(isCurrent && model.state == .connected ? Color.white : Color.primary)
                    .font(.system(size: 13))
            }
            .frame(width: 26, height: 26)
            .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 1) {
                Text(profile.spec.name)
                Group {
                    if isCurrent, let st = model.status {
                        ConnectionSummary(status: st)
                    } else {
                        Text(verbatim: profile.spec.endpoint.host)
                    }
                }
                .font(.caption)
                .foregroundStyle(.secondary)
            }
            Spacer(minLength: 8)
            Toggle(profile.spec.name, isOn: isOn)
                .toggleStyle(.switch)
                .controlSize(.small)
                .labelsHidden()
                .disabled(blocked)
                .accessibilityLabel("Connect \(profile.spec.name)")
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 3)
    }
}

/// The daemon's log level. Debug logs protocol exchanges (status codes, cookie names, paths),
/// never passwords, codes or cookie values.
struct LogLevelRow: View {
    @ObservedObject var model: AppModel
    static let levels = ["error", "warn", "info", "debug", "trace"]

    var body: some View {
        HStack {
            Text("Log Level")
            Spacer()
            Picker("Log Level", selection: Binding(
                get: { model.logLevel ?? "" },
                set: { model.setLogLevel($0) })
            ) {
                if model.logLevel == nil { Text("Custom").tag("") }
                ForEach(Self.levels, id: \.self) { Text($0.capitalized).tag($0) }
            }
            .labelsHidden()
            .pickerStyle(.menu)
            .fixedSize()
            .controlSize(.small)
        }
        .padding(.horizontal, 8)
        .disabled(model.serviceError != nil)
        .help("Daemon log verbosity. Secrets are never logged at any level.")
    }
}

/// "Settings…": `openSettings` from macOS 14, the responder-chain action before.
struct SettingsRow: View {
    let willOpen: () -> Void

    var body: some View {
        if #available(macOS 14, *) {
            SettingsRow14(willOpen: willOpen)
        } else {
            MenuRow(title: "Settings…") {
                willOpen()
                NSApp.activate(ignoringOtherApps: true)
                NSApp.sendAction(Selector(("showSettingsWindow:")), to: nil, from: nil)
            }
        }
    }
}

@available(macOS 14, *)
private struct SettingsRow14: View {
    let willOpen: () -> Void
    @Environment(\.openSettings) private var openSettings

    var body: some View {
        MenuRow(title: "Settings…") {
            willOpen()
            NSApp.activate(ignoringOtherApps: true)
            openSettings()
        }
    }
}

/// The window a view is in, kept by reference so reading it doesn't redraw the view.
final class WindowRef {
    weak var window: NSWindow?
}

struct WindowReader: NSViewRepresentable {
    let ref: WindowRef

    final class Probe: NSView {
        var ref: WindowRef?
        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            ref?.window = window
        }
    }

    func makeNSView(context: Context) -> Probe {
        let v = Probe()
        v.ref = ref
        return v
    }

    func updateNSView(_ view: Probe, context: Context) {
        view.ref = ref
        ref.window = view.window
    }
}

/// A full-width row that highlights on hover, like a menu item.
struct MenuRow: View {
    let title: String
    var help: String?
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            Text(title)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .background(
            RoundedRectangle(cornerRadius: 6, style: .continuous)
                .fill(hovering ? Color.primary.opacity(0.1) : .clear)
        )
        .onHover { hovering = $0 }
        .help(help ?? "")
    }
}
