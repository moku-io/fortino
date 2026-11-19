// Sign-in panel shown whenever the daemon has an outstanding challenge for this user.

import AppKit
import OFCKit
import SwiftUI

@MainActor
final class ChallengePanelController {
    weak var model: AppModel?
    private var panel: NSPanel?
    private var shownId: String?

    func update(status: Status) {
        guard let ch = status.challenge else {
            close()
            return
        }
        if ch.id == shownId { return }
        shownId = ch.id
        show(ch, status: status)
    }

    private func show(_ ch: Challenge, status: Status) {
        guard let model else { return }
        let view = ChallengeView(challenge: ch, profileName: status.profileName ?? "VPN",
                                 gateway: status.gateway ?? "", model: model)
        let host = NSHostingController(rootView: view)
        let p = panel ?? NSPanel(contentRect: NSRect(x: 0, y: 0, width: 360, height: 180),
                                 styleMask: [.titled, .closable],
                                 backing: .buffered, defer: false)
        p.title = "Sign in to \(status.profileName ?? "VPN")"
        p.contentViewController = host
        p.isReleasedWhenClosed = false
        // A menu-bar app is usually inactive; keep the prompt visible anyway.
        p.hidesOnDeactivate = false
        p.level = .floating
        p.center()
        panel = p
        NSApp.activate(ignoringOtherApps: true)
        p.makeKeyAndOrderFront(nil)
        p.orderFrontRegardless()
    }

    func close() {
        shownId = nil
        panel?.orderOut(nil)
    }
}

struct ChallengeView: View {
    let challenge: Challenge
    let profileName: String
    let gateway: String
    @ObservedObject var model: AppModel
    @State private var value = ""
    @State private var error: String?
    @State private var busy = false
    @FocusState private var focused: Bool

    private var title: String {
        switch challenge.kind {
        case .username: return "Username"
        case .password: return "Password"
        case .otp: return "One-time code"
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("\(profileName) — \(gateway)").font(.headline)
            Text(challenge.prompt).foregroundStyle(.secondary)
            Group {
                if challenge.kind.isSecret {
                    SecureField(title, text: $value)
                } else {
                    TextField(title, text: $value)
                }
            }
            .textFieldStyle(.roundedBorder)
            .focused($focused)
            .onSubmit(submit)
            .accessibilityLabel(title)
            if let error {
                Text(error).foregroundStyle(.red).font(.callout)
            }
            HStack {
                Button("Cancel connection", role: .cancel) { model.disconnect() }
                Spacer()
                Button("Continue", action: submit)
                    .keyboardShortcut(.defaultAction)
                    .disabled(value.isEmpty || busy)
            }
        }
        .padding(20)
        .frame(width: 360)
        .onAppear { focused = true }
    }

    private func submit() {
        guard !value.isEmpty else { return }
        busy = true
        let v = value
        value = ""
        Task {
            if let e = await model.respond(challenge: challenge, value: v) {
                error = e.code == "stale_challenge"
                    ? "This prompt expired or was answered elsewhere."
                    : e.message
            }
            busy = false
        }
    }
}
