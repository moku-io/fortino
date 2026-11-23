// Debug-only UI for EMS SYSINFO overrides. **Not a normal feature.**
//
// This whole file, the `debugEmsSysinfo` field in `ProfileSpec`, and the three lines that use
// `debugOverrides` in `ProfilesWindow`'s `Draft` are the entire client-side footprint. Deleting
// them removes the feature.

import SwiftUI

/// One editable SYSINFO override row.
struct DebugKV: Identifiable, Equatable {
    let id = UUID()
    var key: String = ""
    var value: String = ""
}

/// Validates the override rows the way the daemon does, so the error shows before saving.
/// Returns `nil` when every non-empty row is a valid `[A-Z0-9_]` key with a one-line value.
func debugOverridesError(_ rows: [DebugKV]) -> String? {
    var seen = Set<String>()
    for row in rows {
        let key = row.key.trimmingCharacters(in: .whitespaces)
        if key.isEmpty {
            if row.value.trimmingCharacters(in: .whitespaces).isEmpty { continue }
            return "A value needs a key."
        }
        let valid = key.count <= 64
            && key.allSatisfy { $0.isUppercase && $0.isLetter || $0.isNumber || $0 == "_" }
        if !valid {
            return "“\(key)” isn’t a valid SYSINFO key (use A–Z, 0–9, _)."
        }
        if row.value.contains(where: \.isNewline) {
            return "“\(key)” has a line break in its value."
        }
        if !seen.insert(key).inserted {
            return "“\(key)” is set more than once."
        }
    }
    return rows.count > 64 ? "Too many overrides." : nil
}

/// Builds the wire map from the rows: non-empty keys only, trimmed keys, verbatim values.
/// `nil` when nothing is set, so the field is omitted entirely.
func debugOverridesMap(_ rows: [DebugKV]) -> [String: String]? {
    var map: [String: String] = [:]
    for row in rows {
        let key = row.key.trimmingCharacters(in: .whitespaces)
        if key.isEmpty { continue }
        map[key] = row.value
    }
    return map.isEmpty ? nil : map
}

/// Rows loaded from a stored profile's map, sorted by key for a stable display.
func debugOverrideRows(_ map: [String: String]?) -> [DebugKV] {
    (map ?? [:]).sorted { $0.key < $1.key }.map { DebugKV(key: $0.key, value: $0.value) }
}

/// A collapsible editor that injects raw SYSINFO key/values into what Fortino reports to this
/// profile's EMS. For protocol testing only; it can send values the machine does not actually
/// have, so it is deliberately an expert, hand-typed box with no field picker.
struct DebugOverridesBox: View {
    @Binding var rows: [DebugKV]
    @State private var expanded = false

    private var error: String? { debugOverridesError(rows) }

    var body: some View {
        Section {
            DisclosureGroup(isExpanded: $expanded) {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Overrides the SYSINFO values sent to this profile's EMS, for testing how the EMS responds. Keys are SYSINFO names, e.g. OSVER, FCTVER, AVSIG_VER. These values may not be truthful — use only for your own EMS testing.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)

                    ForEach($rows) { $row in
                        HStack(spacing: 6) {
                            TextField("KEY", text: $row.key)
                                .textFieldStyle(.roundedBorder)
                                .font(.system(.body, design: .monospaced))
                                .frame(width: 150)
                                .accessibilityLabel("SYSINFO key")
                            TextField("value", text: $row.value)
                                .textFieldStyle(.roundedBorder)
                                .font(.system(.body, design: .monospaced))
                                .accessibilityLabel("SYSINFO value")
                            Button {
                                rows.removeAll { $0.id == row.id }
                            } label: {
                                Image(systemName: "minus.circle.fill")
                                    .foregroundStyle(.secondary)
                            }
                            .buttonStyle(.borderless)
                            .accessibilityLabel("Remove override")
                        }
                    }

                    Button {
                        rows.append(DebugKV())
                    } label: {
                        Label("Add parameter", systemImage: "plus")
                    }
                    .buttonStyle(.borderless)

                    if let error {
                        Text(error).font(.caption).foregroundStyle(.red)
                    }
                }
                .padding(.top, 2)
            } label: {
                Label("Debug: EMS parameters", systemImage: "ladybug")
                    .foregroundStyle(.secondary)
            }
        }
    }
}
