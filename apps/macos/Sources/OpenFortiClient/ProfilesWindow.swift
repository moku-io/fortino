// Profile window: list, New/Edit Profile form (EMS server directly below VPN gateway),
// connection state and Connect/Disconnect.

import OFCKit
import SwiftUI

struct ProfilesWindow: View {
    @ObservedObject var model: AppModel
    @State private var creating = false

    var body: some View {
        NavigationSplitView {
            List(selection: Binding(
                get: { creating ? nil : model.selectedProfile?.id },
                set: { id in
                    creating = false
                    model.select(id)
                })) {
                ForEach(model.profiles) { p in
                    VStack(alignment: .leading) {
                        Text(p.spec.name)
                        Text(p.spec.endpoint.host).font(.caption).foregroundStyle(.secondary)
                    }
                    .tag(p.id)
                }
            }
            .navigationSplitViewColumnWidth(min: 180, ideal: 200)
            .toolbar {
                Button {
                    creating = true
                } label: {
                    Label("New Profile", systemImage: "plus")
                }
            }
        } detail: {
            VStack(spacing: 0) {
                ConnectionBar(model: model)
                Divider()
                if creating {
                    ProfileEditor(model: model, profile: nil) { creating = false }
                        .id("new")
                } else if let p = model.selectedProfile {
                    ProfileEditor(model: model, profile: p, onDone: {})
                        .id(p.id + "-\(p.revision)")
                } else {
                    VStack(spacing: 8) {
                        Text("No profiles").font(.title3)
                        Button("New Profile") { creating = true }
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            }
        }
        .frame(minWidth: 640, minHeight: 460)
        .task {
            await model.refreshProfiles()
            await model.refreshStatus()
        }
        .onChange(of: model.focusEmsFor) { id in
            if id != nil { creating = false }
        }
    }
}

/// Current connection state with the matching action, shown above the editor.
struct ConnectionBar: View {
    @ObservedObject var model: AppModel

    var body: some View {
        HStack(spacing: 10) {
            StatusIcon(state: model.state).font(.title3)
            VStack(alignment: .leading, spacing: 2) {
                Text(model.state.label).font(.headline)
                if let st = model.status, model.state.isActive {
                    Text([st.profileName, st.gateway, st.assignedIp].compactMap { $0 }.joined(separator: " · "))
                        .font(.caption).foregroundStyle(.secondary)
                } else if let r = model.status?.lastResult, let code = r.code, code != "cancelled" {
                    Text("Last attempt: \(r.message)").font(.caption).foregroundStyle(.red)
                }
                if let e = model.serviceError ?? model.actionError {
                    Text(e).font(.caption).foregroundStyle(.red)
                }
            }
            Spacer()
            switch model.state {
            case .connected:
                Button("Disconnect") { model.disconnect() }
            case .starting, .authenticating, .awaitingInput, .configuring:
                Button("Cancel") { model.disconnect() }
            case .idle, .recoveryRequired:
                Button("Connect \(model.selectedProfile?.spec.name ?? "")") { model.connect() }
                    .disabled(model.selectedProfile == nil || model.serviceError != nil)
            default:
                EmptyView()
            }
        }
        .padding(12)
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
            Section(profile == nil ? "New Profile" : "Edit Profile") {
                field("Name", text: $draft.name, key: "name", focus: .name)
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
                field("Realm", text: $draft.realm, key: "realm", focus: .realm, prompt: "optional")
                field("Username", text: $draft.username, key: "username", focus: .username,
                      prompt: "asked when connecting if empty")
                TextField("Description", text: $draft.description)
                Picker("Routing", selection: $draft.policy) {
                    ForEach(IpPolicy.allCases) { Text($0.label).tag($0) }
                }
                Text("Server certificates are always verified.")
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
                    Button("Delete", role: .destructive) { confirmDelete = true }
                        .disabled(isActiveProfile)
                        .confirmationDialog("Delete \(p.spec.name)?", isPresented: $confirmDelete) {
                            Button("Delete", role: .destructive) {
                                Task { serverError = await model.delete(p) }
                            }
                        }
                    if p.spec.endpoint.ems == nil {
                        Button("Set EMS server") { focus = .ems }
                    }
                }
                Spacer()
                if profile == nil {
                    Button("Cancel", action: onDone)
                }
                Button(profile == nil ? "Create" : "Save", action: save)
                    .keyboardShortcut(.defaultAction)
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
