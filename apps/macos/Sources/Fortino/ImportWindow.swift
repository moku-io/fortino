// Import window: preview a FortiClient XML export (parsed by ofctl in this user's process),
// choose entries and replacements, optionally set EMS servers, then commit in one transaction.

import AppKit
import OFCKit
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

struct ImportWindow: View {
    @ObservedObject var model: AppModel
    @State private var file: URL?
    @State private var preview: ImportPreview?
    @State private var selected: Set<Int> = []
    @State private var replace: Set<Int> = []
    @State private var ems: [Int: String] = [:]
    @State private var message: String?
    @State private var busy = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text(file?.lastPathComponent ?? "Choose a FortiClient XML export")
                    .font(.headline)
                Spacer()
                Button("Choose File…", action: choose)
            }
            if let p = preview {
                List {
                    ForEach(p.entries) { e in row(e) }
                    ForEach(p.rejected) { r in
                        Text("#\(r.ordinal) rejected: \(r.field) \(r.code)").foregroundStyle(.red)
                    }
                    if p.excluded_ipsec > 0 {
                        Text("\(p.excluded_ipsec) IPsec connection(s) excluded").foregroundStyle(.secondary)
                    }
                    ForEach(p.notes, id: \.self) { Text($0).foregroundStyle(.secondary) }
                }
            } else {
                Spacer()
                Text("Profiles are checked before anything is saved. Passwords, scripts and UI settings in the file are not imported.")
                    .foregroundStyle(.secondary)
                Spacer()
            }
            if let m = message { Text(m).font(.callout) }
            HStack {
                Spacer()
                Button("Import \(selected.count) Profile(s)", action: commit)
                    .keyboardShortcut(.defaultAction)
                    .disabled(selected.isEmpty || busy)
            }
        }
        .padding(16)
        .frame(minWidth: 560, minHeight: 420)
    }

    private func existing(_ e: PreviewEntry) -> Profile? {
        model.profiles.first { $0.spec.name.lowercased() == e.spec.name.lowercased() }
    }

    @ViewBuilder private func row(_ e: PreviewEntry) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Toggle(isOn: Binding(
                    get: { selected.contains(e.ordinal) },
                    set: { if $0 { selected.insert(e.ordinal) } else { selected.remove(e.ordinal) } })) {
                    Text(e.spec.name).bold()
                }
                .disabled(!e.eligible)
                Text(verbatim: "\(e.spec.endpoint.host):\(String(e.spec.endpoint.port))\(e.spec.endpoint.realm.map { "/\($0)" } ?? "")")
                    .foregroundStyle(.secondary)
            }
            if let r = e.blocked ?? e.skipped {
                Text((e.blocked != nil ? "Blocked: " : "Skipped: ") + r).font(.caption).foregroundStyle(.orange)
            }
            ForEach(e.warnings, id: \.self) { Text("⚠︎ \($0)").font(.caption) }
            ForEach(e.omitted, id: \.self) { Text("Not imported: \($0)").font(.caption).foregroundStyle(.secondary) }
            if e.eligible, existing(e) != nil {
                Toggle("Replace the existing profile with this name", isOn: Binding(
                    get: { replace.contains(e.ordinal) },
                    set: { if $0 { replace.insert(e.ordinal) } else { replace.remove(e.ordinal) } }))
                .font(.caption)
            }
            if e.eligible, selected.contains(e.ordinal) {
                TextField("EMS server (optional)", text: Binding(
                    get: { ems[e.ordinal] ?? "" }, set: { ems[e.ordinal] = $0 }))
                .font(.caption)
                if case let .failure(err) = parseEms(ems[e.ordinal] ?? "") {
                    Text(err.message).font(.caption).foregroundStyle(.red)
                }
            }
        }
        .padding(.vertical, 2)
    }

    private func choose() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.xml]
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        file = url
        Task { await loadPreview(url) }
    }

    private func loadPreview(_ url: URL) async {
        busy = true
        defer { busy = false }
        message = nil
        preview = nil
        let (code, out, err) = await model.runOfctl(["profile", "import", url.path, "--dry-run"])
        guard let env = try? JSONDecoder().decode(Envelope<ImportPreview>.self, from: out) else {
            message = code == 127 ? "ofctl is not installed: \(err)" : "Could not read the file."
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
        Task {
            defer { busy = false }
            let (_, out, _) = await model.runOfctl(args)
            struct R: Decodable { var results: [Res] }
            struct Res: Decodable { var name: String; var id: String; var action: String }
            guard let env = try? JSONDecoder().decode(Envelope<R>.self, from: out) else {
                message = "Import failed."
                return
            }
            if let e = env.error {
                message = e.code == "conflict"
                    ? "\(e.message). Tick “Replace” for profiles that already exist."
                    : e.message
                return
            }
            await model.refreshProfiles()
            // Apply EMS servers entered in the preview.
            for e in chosen {
                guard case let .success(server?) = parseEms(ems[e.ordinal] ?? ""),
                      let prof = model.profiles.first(where: { $0.spec.name == e.spec.name }) else { continue }
                var s = prof.spec
                s.endpoint.ems = server
                _ = await model.save(s, existing: prof)
            }
            let n = env.result?.results.count ?? 0
            message = "Imported \(n) profile(s)."
            preview = nil
            selected = []
        }
    }
}
