// Sign-in panel shown whenever the daemon has an outstanding challenge for this user.

import AppKit
import FortinoKit
import SwiftUI

@MainActor
final class ChallengePanelController {
    weak var model: AppModel?
    private var panel: NSPanel?
    private var shownId: String?
    /// The challenge whose view the panel holds (it may be hidden by its close button).
    private var presentedId: String?

    func update(status: Status) {
        guard let ch = status.challenge else {
            close()
            return
        }
        if ch.id == shownId { return }
        shownId = ch.id
        // A profile that saves its password: try the keychain first and show the panel only if
        // that didn't answer. An answered prompt disappears from the status by itself.
        if ch.kind == .password, let model, let p = model.savingProfile(for: status) {
            Task { @MainActor in
                guard let note = await model.answerFromKeychain(profile: p, status: status, challenge: ch),
                      self.shownId == ch.id, model.status?.challenge?.id == ch.id else { return }
                self.show(ch, status: status, saved: note)
            }
            return
        }
        show(ch, status: status, saved: nil)
    }

    private func show(_ ch: Challenge, status: Status, saved: SavedPasswordNote?) {
        guard let model else { return }
        let view = ChallengeView(challenge: ch, profileName: status.profileName ?? "VPN",
                                 gateway: status.gateway ?? "", saved: saved, model: model)
        let host = NSHostingController(rootView: view)
        let p = panel ?? NSPanel(contentRect: NSRect(x: 0, y: 0, width: 360, height: 180),
                                 styleMask: [.titled, .closable],
                                 backing: .buffered, defer: false)
        p.title = "Sign in to \(status.profileName ?? "VPN")"
        p.contentViewController = host
        presentedId = ch.id
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
        presentedId = nil
        panel?.orderOut(nil)
    }

    /// Shows the panel again for the open prompt after the user closed it: closing hides it,
    /// and the attempt keeps waiting for the answer. Nothing to show while the keychain is
    /// still answering the prompt.
    func reopen() {
        guard let p = panel, let id = model?.status?.challenge?.id, id == presentedId else { return }
        NSApp.activate(ignoringOtherApps: true)
        p.makeKeyAndOrderFront(nil)
        p.orderFrontRegardless()
    }
}

struct ChallengeView: View {
    let challenge: Challenge
    let profileName: String
    let gateway: String
    /// For a password prompt of a profile that saves its password: why the keychain didn't
    /// answer. Nil otherwise.
    let saved: SavedPasswordNote?
    @ObservedObject var model: AppModel
    @State private var value = ""
    @State private var error: String?
    @State private var busy = false
    /// Save (or replace) the saved password with the typed one once connected.
    @State private var remember = true
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
            Label {
                VStack(alignment: .leading, spacing: 2) {
                    Text(profileName).font(.headline)
                    Text(verbatim: account.map { "\($0) · \(gateway)" } ?? gateway)
                        .font(.caption).foregroundStyle(.secondary)
                }
            } icon: {
                Image(systemName: "lock.shield").font(.title2).foregroundStyle(.tint)
            }
            savedPasswordNotice
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
            savedPasswordOptions
            HStack {
                Spacer()
                Button("Cancel Connection", role: .cancel) { model.disconnect() }
                    .keyboardShortcut(.cancelAction)
                Button("Continue", action: submit)
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .disabled(value.isEmpty || busy)
            }
        }
        .padding(20)
        .frame(width: 360)
        .onAppear { focused = true }
    }

    /// Above the prompt: why the keychain didn't answer, or that it did.
    /// The account signing in, once known (not on the username prompt itself).
    private var account: String? {
        guard challenge.kind != .username, let st = model.status,
              let p = model.profiles.first(where: { $0.id == st.profileId }) else { return nil }
        return model.attemptUsername(p, attempt: st.attemptId)
    }

    /// The keychain answered this attempt's password (shown on the code prompt). Read live: the
    /// keychain helper reports back only once the gateway has asked for the code.
    private var passwordFromKeychain: Bool {
        challenge.kind == .otp && model.status?.attemptId != nil
            && model.keychainAnsweredAttempt == model.status?.attemptId
    }

    @ViewBuilder private var savedPasswordNotice: some View {
        switch saved {
        case .rejected:
            notice("The gateway refused the saved password.")
        case .unavailable:
            notice("The saved password couldn't be read from your keychain.")
        case .otherGateway:
            notice("The saved password is for another gateway, so it wasn't sent.")
        case .willSave, nil:
            if passwordFromKeychain {
                Label("Password filled in from your keychain.", systemImage: "key.fill")
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private func notice(_ text: String) -> some View {
        Label {
            Text(text).foregroundStyle(.secondary)
        } icon: {
            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
        }
        .font(.callout)
        .fixedSize(horizontal: false, vertical: true)
    }

    /// Below the field: whether to keep the typed password.
    @ViewBuilder private var savedPasswordOptions: some View {
        switch saved {
        case .willSave:
            Toggle("Save in Keychain after connecting", isOn: $remember)
        case .rejected, .otherGateway:
            Toggle("Replace the saved password after connecting", isOn: $remember)
        case .unavailable, nil:
            EmptyView()
        }
    }

    private func submit() {
        guard !value.isEmpty else { return }
        busy = true
        let v = value
        value = ""
        model.noteTyped(challenge.kind, value: v,
                        savePassword: remember && [.willSave, .rejected, .otherGateway].contains(saved))
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
