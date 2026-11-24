// The "VPN service is outdated" notice, shared by the menu and the app's windows so an update
// left half-done is visible wherever the user is.

import FortinoKit
import SwiftUI

extension ServiceUpdate {
    /// Whether the administrator restart can be offered now (never while a VPN is up).
    static func canRestart(_ state: SessionState) -> Bool {
        state == .idle || state == .recoveryRequired
    }

    func message(state: SessionState) -> String {
        switch self {
        case .afterDisconnect:
            return "Fortino was updated. The VPN service switches to the new version when you disconnect."
        case .restarting:
            return "Restarting the VPN service…"
        case .otherCopy:
            return "The VPN service belongs to another copy of Fortino. Keep one copy in Applications and open it from there."
        case .needsAdminRestart:
            return Self.canRestart(state)
                ? "The VPN service is from an older version of Fortino. Restart it to finish the update."
                : "The VPN service is from an older version of Fortino. Disconnect, then restart it."
        }
    }

    var symbol: String {
        switch self {
        case .afterDisconnect, .needsAdminRestart: return "arrow.down.circle"
        case .restarting: return "arrow.triangle.2.circlepath"
        case .otherCopy: return "exclamationmark.triangle.fill"
        }
    }

    var tint: Color {
        switch self {
        case .afterDisconnect, .restarting: return .secondary
        case .otherCopy, .needsAdminRestart: return .orange
        }
    }

    func offersRestart(state: SessionState) -> Bool {
        self == .needsAdminRestart && Self.canRestart(state)
    }
}

/// A bar across the top of a window while the VPN service and the app are out of step.
struct ServiceUpdateBanner: View {
    @ObservedObject var model: AppModel

    var body: some View {
        if let u = model.serviceUpdate {
            VStack(spacing: 0) {
                HStack(spacing: 10) {
                    Image(systemName: u.symbol).foregroundStyle(u.tint).imageScale(.large)
                    // No fixedSize here: inside a window's safe-area inset it made the
                    // Profiles split view lay out taller than the window, pushing the profile
                    // list out of sight. Two lines fit every message at the window's minimum width.
                    Text(u.message(state: model.state))
                        .lineLimit(2)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    Spacer(minLength: 8)
                    if u == .restarting {
                        ProgressView().controlSize(.small)
                    } else if u.offersRestart(state: model.state) {
                        Button("Restart VPN Service…") { model.restartServiceAsAdmin() }
                            .help("Asks for an administrator's password")
                    }
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 8)
                Divider()
            }
            .background(.bar)
        }
    }
}
