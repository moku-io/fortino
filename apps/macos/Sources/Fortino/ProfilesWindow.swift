// Profile window: list, New/Edit Profile form (EMS server directly below VPN gateway),
// connection state and Connect/Disconnect.

import FortinoKit
import SwiftUI

struct ProfilesWindow: View {
    @ObservedObject var model: AppModel
    @State private var creating = false
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        NavigationSplitView {
            List(selection: Binding(
                get: { creating ? nil : model.selectedProfile?.id },
                set: { id in
                    creating = false
                    model.select(id)
                })) {
                ForEach(model.profiles) { p in
                    Label {
                        VStack(alignment: .leading) {
                            Text(p.spec.name)
                            Text(verbatim: p.spec.endpoint.host).font(.caption).foregroundStyle(.secondary)
                        }
                    } icon: {
                        Image(systemName: model.status?.profileId == p.id && model.state == .connected
                              ? "lock.shield.fill" : "network.badge.shield.half.filled")
                    }
                    .tag(p.id)
                    .contextMenu {
                        Button("Set EMS Server…") { model.setEmsServer(for: p.id) }
                    }
                }
            }
            .listStyle(.sidebar)
            .navigationSplitViewColumnWidth(min: 190, ideal: 220)
            .overlay {
                if model.profiles.isEmpty && !creating {
                    Text("No Profiles").foregroundStyle(.secondary)
                }
            }
        } detail: {
            Group {
                if creating {
                    ProfileEditor(model: model, profile: nil) { creating = false }
                        .id("new")
                } else if let p = model.selectedProfile {
                    ProfileEditor(model: model, profile: p, onDone: {})
                        .id(p.id + "-\(p.revision)")
                } else {
                    ContentUnavailableCompat(
                        title: "No VPN Profiles",
                        symbol: "network.badge.shield.half.filled",
                        message: "Add a profile for your FortiGate gateway, or import one from FortiClient.")
                }
            }
            .safeAreaInset(edge: .top, spacing: 0) { ServiceUpdateBanner(model: model) }
            .navigationTitle(creating ? "New Profile" : (model.selectedProfile?.spec.name ?? "VPN Profiles"))
        }
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                Button {
                    creating = true
                } label: {
                    Label("New Profile", systemImage: "plus")
                }
                .keyboardShortcut("n", modifiers: .command)
                .help("New Profile")
                Button {
                    openWindow(id: "import")
                } label: {
                    Label("Import", systemImage: "square.and.arrow.down")
                }
                .help("Import from FortiClient")
            }
            ToolbarItem(placement: .primaryAction) {
                ConnectButton(model: model)
            }
        }
        .frame(minWidth: 680, minHeight: 500)
        .task {
            await model.refreshProfiles()
            await model.refreshStatus()
        }
        .onChange(of: model.focusEmsFor) { id in
            if id != nil { creating = false }
        }
    }
}

/// `ContentUnavailableView` exists from macOS 14; this keeps macOS 13 working.
struct ContentUnavailableCompat: View {
    let title: String
    let symbol: String
    let message: String

    var body: some View {
        if #available(macOS 14, *) {
            ContentUnavailableView(title, systemImage: symbol, description: Text(message))
        } else {
            VStack(spacing: 8) {
                Image(systemName: symbol).font(.system(size: 40)).foregroundStyle(.secondary)
                Text(title).font(.title2)
                Text(message).foregroundStyle(.secondary).multilineTextAlignment(.center)
            }
            .padding()
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }
}

/// The toolbar's primary action for the selected profile.
struct ConnectButton: View {
    @ObservedObject var model: AppModel

    /// The active attempt belongs to a profile other than the selected one.
    private var otherActive: Bool {
        model.state.isActive && model.status?.profileId != model.selectedProfile?.id
    }

    var body: some View {
        if otherActive {
            Button("Connect") {}
                .disabled(true)
                .help("Disconnect \(model.status?.profileName ?? "the active profile") first")
        } else {
            actions
        }
    }

    @ViewBuilder private var actions: some View {
        switch model.state {
        case .connected:
            Button("Disconnect") { model.disconnect() }
        case .starting, .authenticating, .awaitingInput, .configuring:
            Button("Cancel") { model.disconnect() }
        case .stopping:
            Button("Disconnecting…") {}.disabled(true)
        case .inUse:
            Button("In Use") {}.disabled(true).help("Another user on this Mac is connected")
        case .idle, .recoveryRequired:
            Button("Connect") { model.connect() }
                .buttonStyle(.borderedProminent)
                .disabled(model.selectedProfile == nil || model.serviceError != nil)
        }
    }
}

/// Connection status for one profile, shown as the first form section.
struct ConnectionSection: View {
    @ObservedObject var model: AppModel
    let profile: Profile

    private var isCurrent: Bool { model.status?.profileId == profile.id }

    var body: some View {
        Section {
            LabeledContent("Status") {
                HStack(spacing: 6) {
                    StatusDot(color: dotColor)
                    Text(isCurrent && model.state.isActive ? model.state.label : "Not Connected")
                }
            }
            if let ems = profile.spec.endpoint.ems {
                EmsStatusRow(model: model, server: ems, status: model.emsStatus[ems.display])
            }
            if isCurrent, model.state == .connected, let st = model.status {
                if let ip = st.assignedIp { LabeledContent("Address", value: ip) }
                if let i = st.interface { LabeledContent("Interface", value: i) }
                LabeledContent("Connected for") { ConnectionSummaryDuration(status: st) }
            }
            if isCurrent, model.state == .idle, let r = model.status?.lastResult,
               let code = r.code, code != "cancelled" {
                LabeledContent("Last Attempt") {
                    if r.attemptId == model.reviewedEmsFailure {
                        Text("EMS certificate trusted. Connect again.").foregroundStyle(.secondary)
                    } else {
                        Text(r.message).foregroundStyle(.red)
                    }
                }
            }
            if let e = model.serviceError ?? model.actionError {
                Text(e).foregroundStyle(.red)
            }
        }
    }

    private var dotColor: Color {
        guard isCurrent else { return .secondary }
        switch model.state {
        case .connected: return .green
        case .idle: return .secondary
        case .recoveryRequired: return .orange
        default: return .yellow
        }
    }
}

struct StatusDot: View {
    let color: Color

    var body: some View {
        Circle().fill(color).frame(width: 8, height: 8).accessibilityHidden(true)
    }
}

/// EMS registration state for the profile's EMS server.
struct EmsStatusRow: View {
    @ObservedObject var model: AppModel
    let server: EmsServer
    let status: EmsStatus?
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        LabeledContent("EMS") {
            HStack(spacing: 6) {
                StatusDot(color: color)
                Text(label)
                if emsTrustFailed {
                    // The last connect failed verifying this EMS (e.g. reached by an address its
                    // certificate doesn't name): show the certificate and offer to pin it.
                    Button("Review Certificate…") { model.approveEms(server) }
                        .controlSize(.small)
                } else if status?.state == "unconfigured" {
                    // Approving is enough for a Mac the EMS already knows: it registers on the
                    // next connect. A DMG is only needed for a Mac the EMS has never seen.
                    Button("Approve…") { model.approveEms(server) }
                        .controlSize(.small)
                        .help("Lets Fortino register this Mac with this EMS server when you connect")
                }
            }
            .help(status?.state == "not-registered"
                  ? "Nothing to do: Fortino registers this Mac with the EMS the next time you connect. For a Mac the EMS has never seen, the administrator may also supply a deployment DMG (Enroll with EMS… in the menu)."
                  : detail)
        }
    }

    private var emsTrustFailed: Bool {
        guard model.state == .idle, let r = model.status?.lastResult,
              r.attemptId != model.reviewedEmsFailure else { return false }
        return r.code == "trust_failure" && r.message.hasPrefix("EMS:")
    }

    private var color: Color {
        switch status?.state {
        case "registered": return .green
        case "stale": return .yellow
        case "quarantined": return .red
        default: return .secondary
        }
    }

    private var label: String {
        switch status?.state {
        case "registered": return "Registered"
        case "stale": return "Registered, no recent check-in"
        case "quarantined": return "Quarantined"
        case "managed-by-forticlient": return "Managed by FortiClient"
        // No administrator has approved this server on this Mac yet.
        case "unconfigured": return "Not Approved"
        case "not-registered": return "Registers When You Connect"
        default: return "Unavailable"
        }
    }

    private var detail: String {
        guard let t = status?.lastKeepalive else { return "" }
        let ago = max(0, Int(Date().timeIntervalSince1970) - t)
        return "Last check-in \(formatDuration(ago)) ago"
    }
}

struct ConnectionSummaryDuration: View {
    let status: Status

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { ctx in
            Text(verbatim: formatDuration(max(0, Int(ctx.date.timeIntervalSince1970) - (status.connectedSince ?? 0))))
        }
    }
}

/// Editable copy of a profile.
struct Draft {
    var name = ""
    var host = ""
    var port = "443"
    var ems = ""
    var realm = ""
    var username = ""
    var description = ""
    var policy: IpPolicy = .splitIpv4

    init() {}

    init(_ p: Profile) {
        let s = p.spec
        name = s.name
        host = s.endpoint.host
        port = String(s.endpoint.port)
        ems = s.endpoint.ems?.display ?? ""
        realm = s.endpoint.realm ?? ""
        username = s.usernameHint ?? ""
        description = s.description ?? ""
        policy = s.ipPolicy
    }

    var errors: [String: String] {
        var e: [String: String] = [:]
        if name.trimmingCharacters(in: .whitespaces).isEmpty { e["name"] = "Enter a name" }
        if case let .error(m) = checkHost(host) { e["host"] = m }
        if case let .error(m) = checkPort(port) { e["port"] = m }
        if case let .failure(err) = parseEms(ems) { e["ems"] = err.message }
        if case let .error(m) = checkRealm(realm) { e["realm"] = m }
        return e
    }

    /// The effective EMS port shown under the field.
    var emsHint: String {
        switch parseEms(ems) {
        case .success(let s?): return "Port \(s.port)" + (ems.contains(":") ? "" : " (default)")
        case .success(nil): return "Optional. Default port \(defaultEmsPort)."
        case .failure: return ""
        }
    }

    func spec(base: ProfileSpec?) -> ProfileSpec? {
        guard errors.isEmpty, let port = Int(port), case let .success(ems) = parseEms(ems) else { return nil }
        let t = { (s: String) -> String? in
            let v = s.trimmingCharacters(in: .whitespaces)
            return v.isEmpty ? nil : v
        }
        var s = base ?? ProfileSpec(name: name, endpoint: Endpoint(host: host))
        s.name = name.trimmingCharacters(in: .whitespaces)
        s.endpoint = Endpoint(host: host.trimmingCharacters(in: .whitespaces).lowercased(),
                              port: port, realm: t(realm), ems: ems)
        s.usernameHint = t(username)
        s.description = t(description)
        s.ipPolicy = policy
        return s
    }
}

struct ProfileEditor: View {
    @ObservedObject var model: AppModel
    let profile: Profile?
    let onDone: () -> Void

    @State private var draft = Draft()
    @State private var serverError: ProtoError?
    @State private var saving = false
    @State private var confirmDelete = false
    @FocusState private var focus: Field?

    enum Field: Hashable { case name, host, port, ems, realm, username }

    private var isActiveProfile: Bool {
        guard let p = profile, let st = model.status else { return false }
        return st.state.isActive && st.profileId == p.id
    }

    private var errors: [String: String] { draft.errors }

    private func fieldError(_ key: String) -> String? {
        if let e = errors[key] { return e }
        if let s = serverError, s.field?.hasSuffix(key) == true || (key == "ems" && s.field == "endpoint.ems") {
            return s.message
        }
        return nil
    }

    var body: some View {
        Form {
            if let p = profile {
                ConnectionSection(model: model, profile: p)
            }
            Section("Gateway") {
                HStack(alignment: .firstTextBaseline) {
                    field("VPN gateway", text: $draft.host, key: "host", focus: .host,
                          prompt: "vpn.example.org")
                    TextField("Port", text: $draft.port)
                        .frame(width: 70)
                        .focused($focus, equals: .port)
                        .accessibilityLabel("VPN gateway port")
                }
                if let e = fieldError("port") { errorText(e) }
                VStack(alignment: .leading, spacing: 2) {
                    TextField("EMS server", text: $draft.ems, prompt: Text("ems.example.org:9016"))
                        .focused($focus, equals: .ems)
                        .accessibilityLabel("EMS server")
                    if let e = fieldError("ems") {
                        errorText(e)
                    } else {
                        Text(draft.emsHint).font(.caption).foregroundStyle(.secondary)
                    }
                }
                field("Realm", text: $draft.realm, key: "realm", focus: .realm, prompt: "Optional")
            }
            Section("Account") {
                field("Name", text: $draft.name, key: "name", focus: .name)
                field("Username", text: $draft.username, key: "username", focus: .username,
                      prompt: "Asked when connecting")
                TextField("Description", text: $draft.description, prompt: Text("Optional"))
            }
            Section {
                Picker("Routing", selection: $draft.policy) {
                    ForEach(IpPolicy.allCases) { Text($0.label).tag($0) }
                }
            } header: {
                Text("Network")
            } footer: {
                Text("Server certificates are always verified. IPv6 traffic is never sent through the tunnel.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            if let s = serverError, s.field == nil {
                errorText(s.message)
            }
            if isActiveProfile {
                Text("Disconnect before changing this profile.").foregroundStyle(.secondary)
            }
            HStack {
                if let p = profile {
                    Button("Delete Profile…", role: .destructive) { confirmDelete = true }
                        .disabled(isActiveProfile)
                        .confirmationDialog("Delete \(p.spec.name)?", isPresented: $confirmDelete) {
                            Button("Delete", role: .destructive) {
                                Task { serverError = await model.delete(p) }
                            }
                        }
                }
                Spacer()
                if profile == nil {
                    Button("Cancel", action: onDone)
                }
                Button(profile == nil ? "Create" : "Save", action: save)
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .disabled(!errors.isEmpty || saving || isActiveProfile)
            }
        }
        .formStyle(.grouped)
        .onAppear {
            if let p = profile { draft = Draft(p) }
            if let id = model.focusEmsFor, id == profile?.id {
                focus = .ems
                model.focusEmsFor = nil
            }
        }
        .onChange(of: model.focusEmsFor) { id in
            if let id, id == profile?.id {
                focus = .ems
                model.focusEmsFor = nil
            }
        }
    }

    private func field(_ label: String, text: Binding<String>, key: String, focus f: Field,
                       prompt: String? = nil) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            TextField(label, text: text, prompt: prompt.map { Text($0) })
                .focused($focus, equals: f)
                .accessibilityLabel(label)
            if let e = fieldError(key) { errorText(e) }
        }
    }

    private func errorText(_ s: String) -> some View {
        Text(s).font(.caption).foregroundStyle(.red)
    }

    private func save() {
        guard let spec = draft.spec(base: profile?.spec) else { return }
        saving = true
        serverError = nil
        Task {
            if let e = await model.save(spec, existing: profile) {
                serverError = e
                if e.code == "stale_revision" {
                    serverError = ProtoError(code: e.code, message: "This profile was changed elsewhere. It has been reloaded; review and save again.")
                    await model.refreshProfiles()
                }
            } else if profile == nil {
                onDone()
            }
            saving = false
        }
    }
}
