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
                        message: "Add a profile for your FortiGate gateway, or import one from FortiClient."
                    ) {
                        HStack {
                            Button("Import from FortiClient…") { openWindow(id: "import") }
                            Button("New Profile") { creating = true }
                                .keyboardShortcut(.defaultAction)
                        }
                        .fixedSize()
                    }
                }
            }
            .safeAreaInset(edge: .top, spacing: 0) { ServiceUpdateBanner(model: model) }
            .navigationTitle(creating ? "New Profile" : (model.selectedProfile?.spec.name ?? "VPN Profiles"))
        }
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                // Click adds a profile; the arrow also offers the import, which is rare enough
                // not to need its own toolbar button. ⌘N and ⇧⌘I are in the File menu.
                Menu {
                    Button("New Profile") { creating = true }
                    Button("Import from FortiClient…") { openWindow(id: "import") }
                    Button("Export to FortiClient…") { Task { await model.exportProfiles() } }
                        .disabled(model.profiles.isEmpty)
                } label: {
                    Label("New Profile", systemImage: "plus")
                } primaryAction: {
                    creating = true
                }
                .help("New Profile")
                // Without it VoiceOver names the toolbar item after the symbol ("add").
                .accessibilityLabel("New Profile")
            }
            ToolbarItem(placement: .primaryAction) {
                ConnectButton(model: model, creating: creating)
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
        .onChange(of: model.newProfileRequested) { _ in takeNewProfileRequest() }
        .onAppear { takeNewProfileRequest() }
    }

    private func takeNewProfileRequest() {
        guard model.newProfileRequested else { return }
        model.newProfileRequested = false
        creating = true
    }
}

/// `ContentUnavailableView` exists from macOS 14; this keeps macOS 13 working.
struct ContentUnavailableCompat<Actions: View>: View {
    let title: String
    let symbol: String
    let message: String
    @ViewBuilder var actions: () -> Actions

    var body: some View {
        if #available(macOS 14, *) {
            ContentUnavailableView {
                Label(title, systemImage: symbol)
            } description: {
                Text(message)
            } actions: {
                actions()
            }
        } else {
            VStack(spacing: 8) {
                Image(systemName: symbol).font(.system(size: 40)).foregroundStyle(.secondary)
                Text(title).font(.title2)
                Text(message).foregroundStyle(.secondary).multilineTextAlignment(.center)
                actions().padding(.top, 8)
            }
            .padding()
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }
}

/// The toolbar's primary action for the selected profile.
struct ConnectButton: View {
    @ObservedObject var model: AppModel
    /// The new-profile form is shown: Connect would act on another, hidden profile.
    var creating = false

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
            Button("Connect") { model.connect(savingEdits: true) }
                .buttonStyle(.borderedProminent)
                .disabled(creating || model.selectedProfile == nil || model.serviceError != nil)
                .help(creating ? "Create the profile first" : "")
        }
    }
}

/// Connection status for one profile, shown as the first form section.
struct ConnectionSection: View {
    @ObservedObject var model: AppModel
    let profile: Profile
    @Environment(\.openWindow) private var openWindow

    private var isCurrent: Bool { model.status?.profileId == profile.id }

    var body: some View {
        Section {
            LabeledContent("Status") {
                HStack(spacing: 6) {
                    StatusDot(color: dotColor)
                    Text(isCurrent && model.state.isActive ? model.state.label : "Not Connected")
                    if isCurrent, model.state == .awaitingInput, model.status?.challenge != nil {
                        Button("Sign In…") { model.showSignIn() }
                            .controlSize(.small)
                            .help("Shows the sign-in panel")
                    }
                }
            }
            if let ems = profile.spec.endpoint.ems {
                EmsStatusRow(model: model, profileId: profile.id, server: ems,
                             status: model.emsStatus[ems.display])
                if model.emsStatus[ems.display]?.checkedInWithoutRules == true {
                    EmsNoRulesNote(model: model, profileId: profile.id)
                }
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
                    } else if r.attemptId == model.reviewedGatewayFailure {
                        Text("Gateway certificate trusted. Connect again.").foregroundStyle(.secondary)
                    } else {
                        VStack(alignment: .trailing, spacing: 6) {
                            Text(r.message).foregroundStyle(.red)
                            if r.code == "auth_denied", model.keychainAnsweredAttempt == r.attemptId {
                                Text("The saved password was refused. You'll be asked for it next time.")
                                    .font(.callout).foregroundStyle(.secondary)
                            }
                            if model.lastAttemptNeedsEms(profile) {
                                Button("Open EMS Setup…") {
                                    model.emsSetupProfileId = profile.id
                                    openWindow(id: "ems-setup")
                                    NSApp.activate(ignoringOtherApps: true)
                                }
                                .controlSize(.small)
                                .help("Shows which EMS step is missing and how to complete it")
                            }
                            if model.gatewayTrustFailure?.id == profile.id {
                                Button("Review Certificate…") { model.reviewGatewayCertificate(profile) }
                                    .controlSize(.small)
                                    .help("Shows the gateway's certificate and lets you trust it on this Mac")
                            }
                        }
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
/// The EMS accepted this Mac but assigned it nothing. Often harmless, but on gateways that admit
/// devices by EMS tag it explains a VPN that connects while nothing loads.
struct EmsNoRulesNote: View {
    @ObservedObject var model: AppModel
    let profileId: String
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label {
                VStack(alignment: .leading, spacing: 2) {
                    Text("The EMS sent no compliance rules for this Mac").fontWeight(.medium)
                    Text("It may not recognize this Mac yet, or its policy may not accept it, for example because of the macOS version or missing antivirus. If the VPN connects but company resources don't load, enroll with your organization's FortiClient package or ask your IT administrator.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            } icon: {
                Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
            }
            HStack {
                Spacer()
                Button("Enroll with Package…") {
                    // The package is checked against this profile's EMS.
                    model.emsSetupProfileId = profileId
                    openWindow(id: "enrollment")
                    NSApp.activate(ignoringOtherApps: true)
                }
            }
        }
        .padding(.vertical, 2)
    }
}

struct EmsStatusRow: View {
    @ObservedObject var model: AppModel
    let profileId: String
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
                } else {
                    // Every EMS step (allow, register, package, roadblocks) is in EMS Setup.
                    Button(needsSetup ? "Set Up…" : "Details…") {
                        model.emsSetupProfileId = profileId
                        openWindow(id: "ems-setup")
                        NSApp.activate(ignoringOtherApps: true)
                    }
                    .controlSize(.small)
                    .help("Guided EMS setup: allow the server, register this Mac, and see what is in the way")
                }
            }
            .help(status?.state == "not-registered"
                  ? "Fortino registers this Mac with the EMS the next time you connect, or now from EMS Setup."
                  : detail)
        }
    }

    private var needsSetup: Bool {
        ["unconfigured", "not-registered", "held-by-forticlient", "quarantined", nil].contains(status?.state)
    }

    /// The last attempt failed verifying this EMS server (its own profile's, or another
    /// profile's with the same server).
    private var emsTrustFailed: Bool {
        guard model.state == .idle, let st = model.status, let r = st.lastResult,
              r.attemptId != model.reviewedEmsFailure,
              model.profiles.first(where: { $0.id == st.profileId })?.spec.endpoint.ems == server
        else { return false }
        return r.code == "trust_failure" && r.message.hasPrefix("EMS:")
    }

    private var color: Color {
        switch status?.state {
        case "registered": return .green
        // Keepalives run only while connected, so a quiet registration is normal when idle.
        case "stale": return .secondary
        case "quarantined": return .red
        case "held-by-forticlient": return .orange
        default: return .secondary
        }
    }

    private var label: String {
        switch status?.state {
        case "registered": return "Registered"
        case "stale": return "Registered"
        case "quarantined": return "Quarantined"
        case "managed-by-forticlient": return "Managed by FortiClient"
        case "held-by-forticlient": return "Held by FortiClient"
        // No administrator has approved this server on this Mac yet.
        case "unconfigured": return "Not Approved"
        case "not-registered": return "Registers When You Connect"
        default: return "Unavailable"
        }
    }

    private var detail: String {
        guard let t = status?.lastKeepalive else { return "" }
        let ago = max(0, Int(Date().timeIntervalSince1970) - t)
        return "Last check-in with the EMS \(formatDuration(ago)) ago. Fortino checks in while the VPN is connected."
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
    var dns: DnsMode = .gateway
    var savePassword = false
    /// Debug only: EMS SYSINFO overrides. See DebugOverridesBox.swift.
    var debugOverrides: [DebugKV] = []

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
        dns = s.dnsMode ?? .gateway
        savePassword = s.savePassword ?? false
        debugOverrides = debugOverrideRows(s.debugEmsSysinfo)
    }

    var errors: [String: String] {
        var e: [String: String] = [:]
        if name.trimmingCharacters(in: .whitespaces).isEmpty { e["name"] = "Enter a name" }
        if case let .error(m) = checkHost(host) { e["host"] = m }
        if case let .error(m) = checkPort(port) { e["port"] = m }
        if case let .failure(err) = parseEms(ems) { e["ems"] = err.message }
        if case let .error(m) = checkRealm(realm) { e["realm"] = m }
        if savePassword && !hasUsername { e["username"] = "Required while Save password is on." }
        if let m = debugOverridesError(debugOverrides) { e["debug"] = m }
        return e
    }

    var hasUsername: Bool { !username.trimmingCharacters(in: .whitespaces).isEmpty }

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
        s.dnsMode = dns == .gateway ? nil : dns
        s.savePassword = savePassword ? true : nil
        s.debugEmsSysinfo = debugOverridesMap(debugOverrides)
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
    /// Fields the user has edited; a new profile shows a field's error only after that, or
    /// after Create, so an empty form doesn't open covered in red.
    @State private var touched: Set<String> = []
    @State private var attempted = false
    /// Tells this editor's pending edits apart from the next editor's when the view is replaced.
    @State private var editorId = UUID()
    @FocusState private var focus: Field?

    enum Field: Hashable { case name, host, port, ems, realm, username }

    private var isActiveProfile: Bool {
        guard let p = profile, let st = model.status else { return false }
        return st.state.isActive && st.profileId == p.id
    }

    private var errors: [String: String] { draft.errors }

    private func fieldError(_ key: String) -> String? {
        if let e = errors[key], profile != nil || attempted || touched.contains(key) { return e }
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
                        .onChange(of: draft.port) { _ in touched.insert("port") }
                        .accessibilityLabel("VPN gateway port")
                }
                if let e = fieldError("port") { errorText(e) }
                VStack(alignment: .leading, spacing: 2) {
                    TextField("EMS server", text: $draft.ems, prompt: Text("ems.example.org:9016"))
                        .focused($focus, equals: .ems)
                        .onChange(of: draft.ems) { _ in touched.insert("ems") }
                        .accessibilityLabel("EMS server")
                    if let e = fieldError("ems") {
                        errorText(e)
                    } else {
                        Text(draft.emsHint).font(.caption).foregroundStyle(.secondary)
                    }
                }
                field("Realm", text: $draft.realm, key: "realm", focus: .realm, prompt: "Optional")
            }
            Section {
                field("Name", text: $draft.name, key: "name", focus: .name, prompt: "Required")
                field("Username", text: $draft.username, key: "username", focus: .username,
                      prompt: draft.savePassword ? "Required" : "Asked when connecting")
                TextField("Description", text: $draft.description, prompt: Text("Optional"))
                // A password is saved for one account, so the toggle waits for the username. It
                // stays usable while on, so clearing the username can be resolved either way.
                Toggle("Save password in Keychain", isOn: $draft.savePassword)
                    .disabled(!draft.hasUsername && !draft.savePassword)
                    .help(draft.hasUsername || draft.savePassword
                          ? "" : "Enter the username you sign in with first")
                if let p = profile, p.spec.savePassword == true, draft.savePassword {
                    SavedPasswordRow(model: model, profile: p)
                }
            } header: {
                Text("Account")
            } footer: {
                Group {
                    if draft.savePassword {
                        Text("Saved in your login keychain after you connect, and filled in next time. One-time codes are always asked for. Turning this off removes the saved password.")
                    } else if !draft.hasUsername {
                        Text("To save the password, enter the username you sign in with.")
                    }
                }
                .font(.caption).foregroundStyle(.secondary)
                .multilineTextAlignment(.leading)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            Section {
                Picker("Routing", selection: $draft.policy) {
                    ForEach(IpPolicy.allCases) { Text($0.label).tag($0) }
                }
                Picker("DNS", selection: $draft.dns) {
                    ForEach(DnsMode.allCases) { Text($0.label).tag($0) }
                }
            } header: {
                Text("Network")
            } footer: {
                VStack(alignment: .leading, spacing: 4) {
                    if draft.dns == .local {
                        Text("This Mac's DNS answers every name. Names only the VPN's DNS knows won't resolve.")
                    }
                    Text("Server certificates are always verified. IPv6 traffic is never sent through the tunnel.")
                }
                .font(.caption).foregroundStyle(.secondary)
                .multilineTextAlignment(.leading)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            DebugOverridesBox(rows: $draft.debugOverrides)
        }
        .formStyle(.grouped)
        // Pinned below the form so Save stays in view however long the form grows.
        .safeAreaInset(edge: .bottom, spacing: 0) { actionBar }
        .onAppear {
            if let p = profile { draft = Draft(p) }
            registerEdits()
            if let id = model.focusEmsFor, id == profile?.id {
                focus = .ems
                model.focusEmsFor = nil
            }
        }
        .onChange(of: hasChanges) { _ in registerEdits() }
        .onDisappear {
            if model.pendingEdits?.editor == editorId { model.pendingEdits = nil }
        }
        .onChange(of: model.focusEmsFor) { id in
            if let id, id == profile?.id {
                focus = .ems
                model.focusEmsFor = nil
            }
        }
    }

    private var actionBar: some View {
        VStack(alignment: .leading, spacing: 8) {
            if let s = serverError, s.field == nil || s.field == "debugEmsSysinfo" {
                errorText(s.message)
            }
            if isActiveProfile {
                Text("Disconnect before changing this profile.").font(.callout).foregroundStyle(.secondary)
            }
            HStack {
                if let p = profile {
                    Button("Delete Profile…", role: .destructive) { confirmDelete = true }
                        .disabled(isActiveProfile)
                        .confirmationDialog("Delete \(p.spec.name)?", isPresented: $confirmDelete) {
                            Button("Delete", role: .destructive) {
                                Task { serverError = await model.delete(p) }
                            }
                        } message: {
                            if p.spec.savePassword == true {
                                Text("Its saved password is also removed from your login keychain.")
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
                    .disabled(saving || isActiveProfile || !hasChanges
                              || (!errors.isEmpty && (profile != nil || attempted)))
            }
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 12)
        .background(.bar)
        .overlay(alignment: .top) { Divider() }
    }

    /// The form differs from the stored profile. A new profile always counts as changed.
    private var hasChanges: Bool {
        guard let p = profile else { return true }
        // Compare what would be saved, so edits that normalize away (case, spaces) don't count.
        // An invalid form yields no spec and so counts as changed.
        return draft.spec(base: p.spec) != p.spec
    }

    /// Lets the window's Connect button save this editor's changes before connecting.
    private func registerEdits() {
        guard let p = profile else { return }
        if hasChanges {
            model.pendingEdits = .init(editor: editorId, profileId: p.id, save: { await commit() })
        } else if model.pendingEdits?.editor == editorId {
            model.pendingEdits = nil
        }
    }

    private func field(_ label: String, text: Binding<String>, key: String, focus f: Field,
                       prompt: String? = nil) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            TextField(label, text: text, prompt: prompt.map { Text($0) })
                .focused($focus, equals: f)
                .accessibilityLabel(label)
                .onChange(of: text.wrappedValue) { _ in touched.insert(key) }
            if let e = fieldError(key) { errorText(e) }
        }
    }

    private func errorText(_ s: String) -> some View {
        Text(s).font(.caption).foregroundStyle(.red)
    }

    private func save() {
        Task { await commit() }
    }

    /// Saves the form. Returns why it wasn't saved (shown by Connect), or nil once saved.
    @discardableResult
    private func commit() async -> String? {
        attempted = true
        guard errors.isEmpty, let spec = draft.spec(base: profile?.spec) else {
            return "This profile has unsaved changes with errors. Correct them, then connect again."
        }
        saving = true
        serverError = nil
        defer { saving = false }
        if let e = await model.save(spec, existing: profile) {
            serverError = e
            if e.code == "stale_revision" {
                serverError = ProtoError(code: e.code, message: "This profile was changed elsewhere. It has been reloaded; review and save again.")
                await model.refreshProfiles()
            }
            return "Your changes could not be saved: \(serverError?.message ?? e.message)"
        }
        if profile == nil { onDone() }
        return nil
    }
}

/// What the keychain holds for a profile, with a way to remove it.
struct SavedPasswordRow: View {
    @ObservedObject var model: AppModel
    let profile: Profile

    private var state: SavedPasswordState? { model.savedPasswords[profile.id] }

    var body: some View {
        LabeledContent("Saved password") {
            HStack {
                if state?.rejected == true {
                    Label {
                        Text(summary).foregroundStyle(.secondary)
                    } icon: {
                        Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                    }
                } else {
                    Text(summary).foregroundStyle(.secondary)
                }
                if state?.saved == true {
                    Button("Forget") { Task { await model.forgetSavedPassword(profile.id) } }
                        .help("Removes the password from your login keychain")
                }
            }
            .help(state?.error ?? "")
        }
        .task(id: profile.revision) { await model.refreshSavedPassword(profile.id) }
    }

    private var summary: String {
        guard let s = state else { return "Checking…" }
        if s.error != nil { return "Keychain unavailable" }
        guard s.saved else { return "Not saved yet" }
        if let u = s.username, let mine = profile.spec.usernameHint, u != mine {
            return "Saved for \(u), not \(mine); asked next time"
        }
        if s.otherGateway == true { return "Saved for another gateway; asked next time" }
        if s.rejected { return "Refused by the gateway; asked next time" }
        return s.username.map { "Saved for \($0)" } ?? "Saved"
    }
}
