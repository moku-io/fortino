// Single sign-on in the default browser: listen on 127.0.0.1 for the gateway's final redirect,
// open the sign-in page, and answer the challenge with the redirect's query string.

import AppKit
import FortinoKit
import Network
import SwiftUI

/// Listens on 127.0.0.1:`port` for the browser's redirect at the end of a single sign-on. Every
/// request gets a fixed page or an error status, never an echo of what it sent; the first valid
/// callback's query string is reported once.
final class SamlCallbackServer {
    enum Listening {
        case ready
        case portInUse
        case failed(String)
    }

    private let port: Int
    private let queue = DispatchQueue(label: "org.fortino.saml-callback")
    private var listener: NWListener?
    /// Touched on `queue` only.
    private var delivered = false

    init(port: Int) {
        self.port = port
    }

    /// Starts listening. `listening` gets the outcome; `login` gets the callback's query string,
    /// at most once. Both run on the main actor.
    func start(listening: @escaping @MainActor (Listening) -> Void,
               login: @escaping @MainActor (String) -> Void) {
        guard port > 0, port <= Int(UInt16.max), let p = NWEndpoint.Port(rawValue: UInt16(port)) else {
            Task { @MainActor in listening(.failed("The sign-in names an invalid port.")) }
            return
        }
        let params = NWParameters.tcp
        params.allowLocalEndpointReuse = false
        params.requiredInterfaceType = .loopback
        params.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: p)
        let l: NWListener
        do {
            l = try NWListener(using: params)
        } catch {
            Task { @MainActor in listening(Self.outcome(error)) }
            return
        }
        listener = l
        l.stateUpdateHandler = { [weak l] state in
            switch state {
            case .ready:
                Task { @MainActor in listening(.ready) }
            case .failed(let e), .waiting(let e):
                l?.cancel()
                Task { @MainActor in listening(Self.outcome(e)) }
            default:
                break
            }
        }
        l.newConnectionHandler = { [weak self] c in
            guard let self else { return c.cancel() }
            self.serve(c, login: login)
        }
        l.start(queue: queue)
    }

    func cancel() {
        queue.async { [listener] in listener?.cancel() }
        listener = nil
    }

    private static func outcome(_ error: Error) -> Listening {
        if case .posix(let code) = error as? NWError, code == .EADDRINUSE {
            return .portInUse
        }
        return .failed(error.localizedDescription)
    }

    private func serve(_ c: NWConnection, login: @escaping @MainActor (String) -> Void) {
        c.start(queue: queue)
        // One request per connection, and not much time to send it.
        queue.asyncAfter(deadline: .now() + 10) { c.cancel() }
        receive(c, Data(), login: login)
    }

    private func receive(_ c: NWConnection, _ buffer: Data, login: @escaping @MainActor (String) -> Void) {
        c.receive(minimumIncompleteLength: 1, maximumLength: 4096) { [weak self] data, _, complete, error in
            guard let self else { return c.cancel() }
            var buf = buffer
            if let data { buf.append(data) }
            if let end = samlRequestHeadEnd(buf) {
                self.answer(c, head: buf.prefix(end), login: login)
            } else if buf.count > maxSamlRequestHead || complete || error != nil {
                self.reply(c, status: "400 Bad Request", body: "")
            } else {
                self.receive(c, buf, login: login)
            }
        }
    }

    private func answer(_ c: NWConnection, head: Data, login: @escaping @MainActor (String) -> Void) {
        switch samlCallbackRequest(head, port: port) {
        case .login(let query):
            reply(c, status: "200 OK", body: Self.donePage)
            if !delivered {
                delivered = true
                Task { @MainActor in login(query) }
            }
        case .notFound:
            reply(c, status: "404 Not Found", body: "")
        case .bad:
            reply(c, status: "400 Bad Request", body: "")
        }
    }

    private func reply(_ c: NWConnection, status: String, body: String) {
        let head = "HTTP/1.1 \(status)\r\nContent-Type: text/html; charset=utf-8\r\n"
            + "Content-Length: \(body.utf8.count)\r\nCache-Control: no-store\r\n"
            + "Referrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\n"
            + "Connection: close\r\n\r\n"
        c.send(content: Data((head + body).utf8), completion: .contentProcessed { _ in c.cancel() })
    }

    private static let donePage = """
    <!doctype html><html lang="en"><head><meta charset="utf-8">\
    <meta name="viewport" content="width=device-width"><title>Fortino</title></head>\
    <body style="font: 15px -apple-system, system-ui, sans-serif; margin: 3em; line-height: 1.4">\
    <h1 style="font-size: 1.3em">Signed in</h1>\
    <p>Fortino is finishing the connection. You can close this tab.</p></body></html>
    """
}

/// Runs a single sign-on challenge: for an attempt this app started it listens and opens the
/// browser at once; for one started elsewhere (the command line, or before the app restarted) it
/// offers to finish it here.
@MainActor
final class SamlSignInController: ObservableObject {
    enum Phase: Equatable {
        /// Started elsewhere; nothing listens here yet.
        case offer
        case starting
        /// Listening, with the sign-in page open in the browser.
        case waiting
        case portInUse
        case failed(String)
        /// The callback arrived; the service is finishing the connection.
        case finishing
    }

    weak var model: AppModel?
    @Published private(set) var phase: Phase = .offer
    @Published private(set) var profileName = ""
    @Published private(set) var gateway = ""
    @Published private(set) var login: SamlLogin?
    private var challenge: Challenge?
    private var panel: NSPanel?
    private var server: SamlCallbackServer?

    func update(status: Status, ownAttempt: Bool) {
        guard let ch = status.challenge, ch.kind == .saml, let login = ch.saml else {
            close()
            return
        }
        if ch.id == challenge?.id {
            if ownAttempt && phase == .offer { begin() }
            return
        }
        close()
        challenge = ch
        self.login = login
        profileName = status.profileName ?? "VPN"
        gateway = status.gateway ?? ""
        phase = .offer
        show(activate: !ownAttempt)
        if ownAttempt { begin() }
    }

    /// Listens for the callback, then opens the sign-in page.
    func begin() {
        guard let login, ![.starting, .waiting, .finishing].contains(phase) else { return }
        server?.cancel()
        phase = .starting
        let s = SamlCallbackServer(port: login.callbackPort)
        server = s
        s.start(listening: { [weak self, weak s] outcome in
            guard let self, let s, self.server === s else { return }
            switch outcome {
            case .ready:
                self.phase = .waiting
                self.openBrowser()
            case .portInUse:
                self.phase = .portInUse
                self.server = nil
            case .failed(let m):
                self.phase = .failed(m)
                self.server = nil
            }
        }, login: { [weak self, weak s] query in
            guard let self, let s, self.server === s else { return }
            Task { await self.finish(query) }
        })
    }

    func openBrowser() {
        guard let login, login.url.hasPrefix("https://"), let url = URL(string: login.url) else { return }
        NSWorkspace.shared.open(url)
    }

    func cancelConnection() {
        server?.cancel()
        server = nil
        model?.disconnect()
    }

    private func finish(_ query: String) async {
        guard let model, let ch = challenge else { return }
        phase = .finishing
        server?.cancel()
        server = nil
        if let e = await model.respond(challenge: ch, value: query) {
            phase = .failed(e.code == "stale_challenge"
                ? "This sign-in expired or was finished elsewhere."
                : e.message)
        }
    }

    func close() {
        server?.cancel()
        server = nil
        challenge = nil
        login = nil
        panel?.orderOut(nil)
    }

    private func show(activate: Bool) {
        let p = panel ?? NSPanel(contentRect: NSRect(x: 0, y: 0, width: 380, height: 190),
                                 styleMask: [.titled, .closable],
                                 backing: .buffered, defer: false)
        p.title = "Sign in to \(profileName)"
        p.contentViewController = NSHostingController(rootView: SamlSignInView(controller: self))
        p.isReleasedWhenClosed = false
        // Not floating: the browser, where the sign-in happens, goes on top of it.
        p.hidesOnDeactivate = false
        p.center()
        panel = p
        if activate {
            NSApp.activate(ignoringOtherApps: true)
            p.makeKeyAndOrderFront(nil)
        }
        p.orderFrontRegardless()
    }
}

struct SamlSignInView: View {
    @ObservedObject var controller: SamlSignInController

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label {
                VStack(alignment: .leading, spacing: 2) {
                    Text(controller.profileName).font(.headline)
                    Text(verbatim: controller.gateway).font(.caption).foregroundStyle(.secondary)
                }
            } icon: {
                Image(systemName: "person.badge.key").font(.title2).foregroundStyle(.tint)
            }
            message
            HStack {
                Spacer()
                Button("Cancel Connection", role: .cancel) { controller.cancelConnection() }
                    .keyboardShortcut(.cancelAction)
                primaryButton
            }
        }
        .padding(20)
        .frame(width: 380)
    }

    @ViewBuilder private var message: some View {
        switch controller.phase {
        case .offer:
            Text("This sign-in was started outside the app, for example in Terminal. You can finish it here in your browser.")
                .fixedSize(horizontal: false, vertical: true)
        case .starting:
            progress("Opening your browser…")
        case .waiting:
            progress("Complete the sign-in in your browser.")
            Text("Fortino connects on its own once you're signed in.")
                .font(.callout).foregroundStyle(.secondary)
        case .portInUse:
            Text("Another app is using port \(String(controller.login?.callbackPort ?? 0)) on this Mac, so Fortino can't receive the sign-in. Quit that app, then try again.")
                .fixedSize(horizontal: false, vertical: true)
        case .failed(let m):
            Text(m).foregroundStyle(.red).fixedSize(horizontal: false, vertical: true)
        case .finishing:
            progress("Signed in. Connecting…")
        }
    }

    @ViewBuilder private var primaryButton: some View {
        switch controller.phase {
        case .offer:
            Button("Sign In with Browser") { controller.begin() }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
        case .waiting:
            Button("Open Browser Again") { controller.openBrowser() }
        case .portInUse, .failed:
            Button("Try Again") { controller.begin() }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
        case .starting, .finishing:
            EmptyView()
        }
    }

    private func progress(_ text: String) -> some View {
        HStack(spacing: 8) {
            ProgressView().controlSize(.small)
            Text(text)
        }
    }
}
