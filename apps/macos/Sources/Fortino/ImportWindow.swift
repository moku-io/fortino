// Import window: preview a FortiClient XML export (parsed by fortino in this user's process),
// choose entries and replacements, optionally set EMS servers, then commit in one transaction.

import AppKit
import FortinoKit
import SwiftUI
import UniformTypeIdentifiers

struct PreviewEntry: Decodable, Identifiable {
    var ordinal: Int
    var spec: ProfileSpec
    var warnings: [String]
    var omitted: [String]
    var skipped: String?
    var blocked: String?
    var id: Int { ordinal }
    var eligible: Bool { skipped == nil && blocked == nil }
}

struct RejectedEntry: Decodable, Identifiable {
    var ordinal: Int
    var field: String
    var code: String
    var id: Int { ordinal }
}

struct ImportPreview: Decodable {
    var entries: [PreviewEntry]
    var rejected: [RejectedEntry]
    var excluded_ipsec: Int
    var notes: [String]
}

private struct Envelope<T: Decodable>: Decodable {
    var result: T?
    var error: ProtoError?
}

/// Says in plain words why an entry can't be imported; unknown codes are shown as they are.
func importReason(skipped: String?, blocked: String?) -> String? {
    switch blocked ?? skipped {
    case nil: return nil
    case "ssl_vpn_disabled": return "Skipped: SSL VPN is turned off in this file."
    case "saml_unsupported": return "Skipped: uses single sign-on (SAML), which Fortino doesn't support yet."
    case "client_certificate_unsupported":
        return "Can't import: uses a client certificate, which Fortino can't import yet."
    case "multiple_gateways_unsupported":
        return "Can't import: lists several gateways. Add it as a new profile with the gateway you use."
    case "conflicting_ports": return "Can't import: its gateways use different ports."
    case "differing_realms": return "Can't import: its gateways use different realms."
    case "duplicate_name_rename_required":
        return "Can't import: another connection in the file has the same name. Rename one in FortiClient and export again."
    case let code?: return (blocked != nil ? "Can't import: " : "Skipped: ") + code
    }
}

func plural(_ n: Int, _ one: String, _ many: String) -> String {
    "\(n) \(n == 1 ? one : many)"
}

/// The importer's notes are lower-case phrases naming FortiClient keys (`on_connect script`);
/// show them as sentences with words instead of underscores.
func importNote(_ s: String) -> String {
    let t = s.replacingOccurrences(of: "_", with: " ")
    return t.prefix(1).uppercased() + t.dropFirst()
}

/// What the import did, from the CLI's per-entry `action`.
struct ImportOutcome {
    var added: [String] = []
    var replaced: [String] = []
    var unchanged: [String] = []
    var changed: Int { added.count + replaced.count }
}

struct ImportWindow: View {
    @ObservedObject var model: AppModel
    @Environment(\.openWindow) private var openWindow
    @Environment(\.dismiss) private var dismiss
    @State private var file: URL?
    @State private var preview: ImportPreview?
    @State private var selected: Set<Int> = []
    @State private var replace: Set<Int> = []
    @State private var ems: [Int: String] = [:]
    @State private var message: String?
    @State private var busy = false
    @State private var imported: ImportOutcome?
    @State private var dropTargeted = false

    static let fileTypes = [UTType.xml] + [UTType(filenameExtension: "conf")].compactMap { $0 }

    var body: some View {
        Group {
            if let imported {
                done(imported)
            } else if let p = preview {
                previewView(p)
            } else {
                start
            }
        }
        .frame(minWidth: 580, minHeight: 440)
        .dropDestination(for: URL.self) { urls, _ in
            guard let url = urls.first, Self.accepts(url), !busy else { return false }
            load(url)
            return true
        } isTargeted: { dropTargeted = $0 }
    }

    // MARK: States

    /// No file yet: a drop zone with the file picker.
    private var start: some View {
        VStack(spacing: 14) {
            Image(systemName: "square.and.arrow.down.on.square")
                .font(.system(size: 44, weight: .light))
                .foregroundStyle(dropTargeted ? Color.accentColor : .secondary)
            Text("Import from FortiClient").font(.title2.weight(.semibold))
            Text("Drop a FortiClient backup (.conf) or XML export here, or choose the file. Backups saved with a password can't be read.")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
                .frame(maxWidth: 400)
            if busy {
                ProgressView("Reading \(file?.lastPathComponent ?? "file")…").controlSize(.small)
            } else {
                Button("Choose File…", action: choose)
                    .keyboardShortcut(.defaultAction)
                    .controlSize(.large)
            }
            if let message {
                Label(message, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                    .frame(maxWidth: 420)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Text("Profiles are checked before anything is saved. Passwords and scripts in the file are never imported.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 400)
                .padding(.top, 6)
        }
        .padding(28)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .strokeBorder(dropTargeted ? Color.accentColor : Color.secondary.opacity(0.35),
                              style: StrokeStyle(lineWidth: dropTargeted ? 2 : 1, dash: [6, 4]))
                .padding(16)
        )
    }

    private func previewView(_ p: ImportPreview) -> some View {
        let eligible = p.entries.filter(\.eligible)
        return VStack(spacing: 0) {
            HStack(spacing: 10) {
                Image(systemName: "doc.text")
                    .font(.system(size: 26, weight: .light))
                    .foregroundStyle(.secondary)
                    .frame(width: 32)
                VStack(alignment: .leading, spacing: 2) {
                    Text(verbatim: file?.lastPathComponent ?? "").font(.headline)
                    Text(summary(p)).font(.callout).foregroundStyle(.secondary)
                }
                Spacer()
                Button("Choose Another File…", action: choose).disabled(busy)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
            Divider()
            List {
                if !eligible.isEmpty {
                    Section {
                        ForEach(eligible) { e in row(e) }
                    } header: {
                        HStack {
                            Text("Profiles")
                            Spacer()
                            Button(selected.count == eligible.count ? "Deselect All" : "Select All") {
                                selected = selected.count == eligible.count ? [] : Set(eligible.map(\.ordinal))
                            }
                            .buttonStyle(.link)
                            .font(.callout)
                        }
                    }
                }
                let unavailable = p.entries.filter { !$0.eligible }
                if !unavailable.isEmpty || !p.rejected.isEmpty || p.excluded_ipsec > 0 || !p.notes.isEmpty {
                    Section("Not Imported") {
                        ForEach(unavailable) { e in
                            notImportedRow(e.spec.name,
                                           importReason(skipped: e.skipped, blocked: e.blocked) ?? "",
                                           symbol: e.blocked != nil ? "exclamationmark.triangle.fill" : "minus.circle",
                                           tint: e.blocked != nil ? .orange : .secondary)
                        }
                        ForEach(p.rejected) { r in
                            notImportedRow("Connection \(r.ordinal)",
                                           "Couldn't be read (\(r.field): \(r.code)).",
                                           symbol: "xmark.circle", tint: .red)
                        }
                        if p.excluded_ipsec > 0 {
                            notImportedRow(plural(p.excluded_ipsec, "IPsec connection", "IPsec connections"),
                                           "Fortino supports SSL VPN only.",
                                           symbol: "minus.circle", tint: .secondary)
                        }
                        ForEach(p.notes, id: \.self) { n in
                            notImportedRow("Note", importNote(n), symbol: "info.circle", tint: .secondary)
                        }
                    }
                }
            }
            .listStyle(.inset(alternatesRowBackgrounds: false))
            Divider()
            HStack(spacing: 10) {
                if busy { ProgressView().controlSize(.small) }
                if let message {
                    Label(message, systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                        .lineLimit(2)
                }
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button(selected.isEmpty ? "Import" : "Import \(plural(selected.count, "Profile", "Profiles"))",
                       action: commit)
                    .keyboardShortcut(.defaultAction)
                    .disabled(selected.isEmpty || busy)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
        }
    }

    private func done(_ r: ImportOutcome) -> some View {
        VStack(spacing: 14) {
            Image(systemName: r.changed > 0 ? "checkmark.circle.fill" : "equal.circle.fill")
                .font(.system(size: 44))
                .foregroundStyle(r.changed > 0 ? Color.green : Color.secondary)
            Text(r.changed > 0 ? "Imported \(plural(r.changed, "Profile", "Profiles"))" : "Already Up to Date")
                .font(.title2.weight(.semibold))
            VStack(spacing: 4) {
                if !r.added.isEmpty { Text("Added: " + r.added.joined(separator: ", ")) }
                if !r.replaced.isEmpty { Text("Replaced: " + r.replaced.joined(separator: ", ")) }
                if !r.unchanged.isEmpty {
                    Text((r.changed > 0 ? "Already up to date: " : "No changes for ") + r.unchanged.joined(separator: ", "))
                }
            }
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.center)
            .frame(maxWidth: 460)
            if r.changed > 0 {
                Text("Connect from the menu bar. Fortino asks for your password when you connect.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            if let message {
                Label(message, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange)
            }
            HStack {
                Button("Import Another File…") {
                    imported = nil
                    preview = nil
                    message = nil
                    choose()
                }
                Button("Show Profiles") {
                    openWindow(id: "profiles")
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
            }
            .padding(.top, 6)
        }
        .padding(28)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: Rows

    private func existing(_ e: PreviewEntry) -> Profile? {
        model.profiles.first { $0.spec.name.lowercased() == e.spec.name.lowercased() }
    }

    private func endpoint(_ e: PreviewEntry) -> String {
        let ep = e.spec.endpoint
        let port = ep.port == 443 ? "" : ":\(ep.port)"
        return ep.host + port + (ep.realm.map { " · realm \($0)" } ?? "")
    }

    private func row(_ e: PreviewEntry) -> some View {
        let on = selected.contains(e.ordinal)
        return VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline) {
                Toggle(isOn: Binding(
                    get: { on },
                    set: { if $0 { selected.insert(e.ordinal) } else { selected.remove(e.ordinal) } })) {
                    VStack(alignment: .leading, spacing: 1) {
                        Text(e.spec.name).fontWeight(.medium)
                        Text(verbatim: endpoint(e)).font(.callout).foregroundStyle(.secondary)
                    }
                }
                Spacer()
                if existing(e) != nil {
                    Text("Already exists")
                        .font(.caption)
                        .padding(.horizontal, 6).padding(.vertical, 2)
                        .background(Capsule().fill(Color.secondary.opacity(0.15)))
                    Toggle("Replace", isOn: Binding(
                        get: { replace.contains(e.ordinal) },
                        set: { if $0 { replace.insert(e.ordinal) } else { replace.remove(e.ordinal) } }))
                        .controlSize(.small)
                        .disabled(!on)
                        .help("Replace the existing profile with this one. Its username, routing and DNS choices stay; a saved password is removed if the gateway changes.")
                }
            }
            VStack(alignment: .leading, spacing: 4) {
                ForEach(e.warnings, id: \.self) { w in
                    Label {
                        Text(importNote(w))
                    } icon: {
                        Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.yellow)
                    }
                    .font(.callout)
                }
                if !e.omitted.isEmpty {
                    Text("Not imported: " + e.omitted.map { $0.replacingOccurrences(of: "_", with: " ") }.joined(separator: ", "))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                if on {
                    HStack {
                        Text("EMS server").font(.callout).foregroundStyle(.secondary)
                        TextField("Optional, e.g. ems.example.com", text: Binding(
                            get: { ems[e.ordinal] ?? "" }, set: { ems[e.ordinal] = $0 }))
                            .textFieldStyle(.roundedBorder)
                            .controlSize(.small)
                            .frame(maxWidth: 260)
                    }
                    if case let .failure(err) = parseEms(ems[e.ordinal] ?? "") {
                        Text(err.message).font(.caption).foregroundStyle(.red)
                    }
                }
            }
            .padding(.leading, 20)
        }
        .padding(.vertical, 4)
    }

    private func notImportedRow(_ title: String, _ reason: String, symbol: String, tint: Color) -> some View {
        Label {
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                Text(reason)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        } icon: {
            Image(systemName: symbol).foregroundStyle(tint)
        }
        .padding(.vertical, 2)
    }

    private func summary(_ p: ImportPreview) -> String {
        let total = p.entries.count + p.rejected.count
        let eligible = p.entries.filter(\.eligible).count
        var parts = [plural(total, "SSL VPN connection", "SSL VPN connections")]
        if eligible < total { parts.append("\(eligible) can be imported") }
        parts.append("\(selected.count) selected")
        return parts.joined(separator: " · ")
    }

    // MARK: Actions

    static func accepts(_ url: URL) -> Bool {
        ["conf", "xml"].contains(url.pathExtension.lowercased())
    }

    private func choose() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = Self.fileTypes
        panel.allowsMultipleSelection = false
        panel.message = "Choose a FortiClient backup (.conf) or XML export."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        load(url)
    }

    private func load(_ url: URL) {
        selected.removeAll()
        replace.removeAll()
        ems.removeAll()
        imported = nil
        file = url
        Task { await loadPreview(url) }
    }

    private func loadPreview(_ url: URL) async {
        busy = true
        defer { busy = false }
        message = nil
        preview = nil
        let (code, out, err) = await model.runCLI(["profile", "import", url.path, "--dry-run"])
        guard let env = try? JSONDecoder().decode(Envelope<ImportPreview>.self, from: out) else {
            message = code == 127 ? "fortino is not installed: \(err)" : "Could not read the file."
            return
        }
        if let e = env.error {
            message = e.message
            return
        }
        preview = env.result
        selected = Set(env.result?.entries.filter { $0.eligible && $0.warnings.isEmpty }.map(\.ordinal) ?? [])
    }

    private func commit() {
        guard let url = file, let p = preview else { return }
        let chosen = p.entries.filter { selected.contains($0.ordinal) }
        for e in chosen {
            if case .failure = parseEms(ems[e.ordinal] ?? "") {
                message = "Fix the EMS server for \(e.spec.name)."
                return
            }
        }
        var args = ["profile", "import", url.path]
        for e in chosen { args += ["--select", e.spec.name] }
        for e in chosen where replace.contains(e.ordinal) { args += ["--replace", e.spec.name] }
        busy = true
        message = nil
        Task {
            defer { busy = false }
            let (_, out, _) = await model.runCLI(args)
            struct R: Decodable { var results: [Res] }
            struct Res: Decodable { var name: String; var id: String; var action: String }
            guard let env = try? JSONDecoder().decode(Envelope<R>.self, from: out) else {
                message = "Import failed."
                return
            }
            if let e = env.error {
                message = e.code == "conflict"
                    ? "\(e.message). Turn on Replace for profiles that already exist."
                    : e.message
                return
            }
            await model.refreshProfiles()
            // Apply EMS servers entered in the preview.
            var failed: [String] = []
            for e in chosen {
                guard case let .success(server?) = parseEms(ems[e.ordinal] ?? ""),
                      let prof = model.profiles.first(where: { $0.spec.name == e.spec.name }) else { continue }
                var s = prof.spec
                s.endpoint.ems = server
                if await model.save(s, existing: prof) != nil { failed.append(e.spec.name) }
            }
            let results = env.result?.results ?? []
            if let first = results.first(where: { $0.action != "unchanged" }) ?? results.first {
                model.select(first.id)
            }
            message = failed.isEmpty ? nil : "The EMS server could not be saved for " + failed.joined(separator: ", ") + "."
            var outcome = ImportOutcome()
            for r in results {
                switch r.action {
                case "unchanged": outcome.unchanged.append(r.name)
                case "replaced": outcome.replaced.append(r.name)
                default: outcome.added.append(r.name)
                }
            }
            imported = outcome
            preview = nil
            selected = []
        }
    }
}
