// Fortino menu-bar app. Unprivileged: all VPN work happens in fortinod.

import AppKit
import FortinoKit
import SwiftUI

struct FortinoApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var model = AppModel()
    @Environment(\.openWindow) private var openWindow

    var body: some Scene {
        Window("Profiles", id: "profiles") {
            ProfilesWindow(model: model)
                .task {
                    let ids = ProcessInfo.processInfo.environment["FORTINO_DEBUG_OPEN"]?
                        .split(separator: ",").map(String.init) ?? []
                    for id in ids where id != "profiles" { openWindow(id: id) }
                }
        }

        MenuBarExtra {
            MenuView(model: model, service: delegate.service)
        } label: {
            MenuBarIcon(state: model.state)
        }
        .menuBarExtraStyle(.window)

        Window("Import Profiles", id: "import") {
            ImportWindow(model: model)
        }
        Window("Enroll with EMS", id: "enrollment") {
            EnrollmentWindow(model: model)
        }
        // Development aid: the menu content in a normal window (see FORTINO_DEBUG_OPEN).
        Window("Menu Preview", id: "menu-preview") {
            MenuView(model: model, service: delegate.service)
        }
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    let service = VPNService()

    func applicationDidFinishLaunching(_ notification: Notification) {
        service.ensureRegistered()
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }
}

if CommandLine.arguments.dropFirst().first == "--enroll-dmg" {
    let args = Array(CommandLine.arguments.dropFirst(2))
    guard args.count == 1 || (args.count == 2 && args[1] == "--approve-server") else {
        FileHandle.standardError.write(Data("Usage: Fortino --enroll-dmg FILE [--approve-server]\n".utf8))
        exit(2)
    }
    do {
        let package = try EnrollmentPackage.read(URL(fileURLWithPath: args[0]))
        let client = try DaemonClient(path: ProcessInfo.processInfo.environment["FORTINO_SOCKET"] ?? defaultSocketPath)
        _ = try await client.hello()
        var result = try await client.enroll(package)
        if result.status == "approval-required" {
            guard args.count == 2 else {
                throw ProtoError(code: "permission_denied", message: "To approve \(package.address) on this Mac, repeat with --approve-server.")
            }
            print("Approving \(package.address) for enrollment.")
            try EnrollmentApproval(package: package).requestInTerminal()
            result = try await client.enroll(package)
        }
        print("EMS: \(result.status), stored rules: \(result.rules)")
        exit(result.status == "approval-required" ? 1 : 0)
    } catch {
        FileHandle.standardError.write(Data((error.localizedDescription + "\n").utf8))
        exit(1)
    }
} else {
    FortinoApp.main()
}
