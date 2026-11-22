// The root VPN service (fortinod) ships inside Fortino.app and is registered with launchd through
// SMAppService. The user approves it once in System Settings > General > Login Items; moving the
// app to the Trash removes it. Also installs the `fortino` command-line tool on request.

import AppKit
import Foundation
import ServiceManagement

@MainActor
final class VPNService: ObservableObject {
    enum State: Equatable {
        /// Not managed by the app: development daemon (FORTINO_SOCKET) or an app run outside a
        /// bundle.
        case external
        case enabled
        case requiresApproval
        case failed(String)
    }

    static let plistName = "org.fortino.fortinod.plist"
    static let cliLink = "/usr/local/bin/fortino"

    @Published private(set) var state: State = .external
    @Published private(set) var cliInstalled = false
    private let service = SMAppService.daemon(plistName: plistName)

    var isManaged: Bool {
        ProcessInfo.processInfo.environment["FORTINO_SOCKET"] == nil
            && Bundle.main.bundleURL.pathExtension == "app"
    }

    var bundledCLI: String {
        Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/fortino").path
    }

    /// Registers the service if needed and refreshes the state. Safe to call repeatedly.
    func ensureRegistered() {
        refreshCLI()
        guard isManaged else {
            state = .external
            return
        }
        if service.status == .notRegistered || service.status == .notFound {
            do {
                try service.register()
            } catch {
                // Registration that needs the user's approval also throws; the status says so.
                if service.status != .requiresApproval {
                    state = .failed(error.localizedDescription)
                    return
                }
            }
        }
        refresh()
    }

    func refresh() {
        guard isManaged else {
            state = .external
            return
        }
        switch service.status {
        case .enabled: state = .enabled
        case .requiresApproval: state = .requiresApproval
        case .notRegistered, .notFound: state = .failed("The VPN service is not registered.")
        @unknown default: state = .failed("The VPN service is in an unknown state.")
        }
    }

    func openLoginItemsSettings() {
        SMAppService.openSystemSettingsLoginItems()
    }

    /// Restarts the service with an administrator's password: launchd stops it and starts the
    /// binary in this bundle. Only for a service that predates build IDs (newer ones restart
    /// themselves when asked). Returns an error message, or nil on success or cancellation.
    static func restartAsAdmin() -> String? {
        let script = """
        do shell script "launchctl kickstart -k system/org.fortino.fortinod" \
        with prompt "Fortino wants to restart its VPN service to finish an update." \
        with administrator privileges
        """
        var error: NSDictionary?
        NSAppleScript(source: script)?.executeAndReturnError(&error)
        if let error, (error[NSAppleScript.errorNumber] as? Int) != -128 {
            return error[NSAppleScript.errorMessage] as? String ?? "Could not restart the VPN service."
        }
        return nil
    }

    // MARK: Command-line tool

    func refreshCLI() {
        let dest = try? FileManager.default.destinationOfSymbolicLink(atPath: Self.cliLink)
        cliInstalled = dest == bundledCLI
    }

    /// Links /usr/local/bin/fortino to the CLI in the bundle, asking for an administrator's
    /// password. Returns an error message, or nil on success or cancellation.
    func installCLI() -> String? {
        let script = """
        do shell script "mkdir -p /usr/local/bin && ln -sfh " & quoted form of "\(Self.escape(bundledCLI))" & " \
        \(Self.cliLink)" with prompt "Fortino wants to install the fortino command-line tool." \
        with administrator privileges
        """
        var error: NSDictionary?
        NSAppleScript(source: script)?.executeAndReturnError(&error)
        refreshCLI()
        if let error, (error[NSAppleScript.errorNumber] as? Int) != -128 {
            return error[NSAppleScript.errorMessage] as? String ?? "Could not install the command-line tool."
        }
        return nil
    }

    /// Escapes a string for an AppleScript string literal.
    private static func escape(_ s: String) -> String {
        s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
    }
}
