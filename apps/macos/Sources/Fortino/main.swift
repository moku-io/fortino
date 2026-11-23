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
        .commands { FortinoCommands(model: model) }

        MenuBarExtra {
            MenuView(model: model, service: delegate.service)
        } label: {
            MenuBarIcon(state: model.state)
                // Opening Fortino again (Finder, Spotlight) shows the Profiles window, so the app
                // stays reachable when the menu-bar item is hidden behind the notch.
                .onReceive(NotificationCenter.default.publisher(for: .fortinoShowProfiles)) { _ in
                    openWindow(id: "profiles")
                    NSApp.activate(ignoringOtherApps: true)
                }
        }
        .menuBarExtraStyle(.window)

        // Reached from the File menu and the Profiles window, so not listed in the Window menu.
        Window("Import from FortiClient", id: "import") {
            ImportWindow(model: model)
        }
        .defaultSize(width: 680, height: 640)
        .commandsRemoved()
        Window("Enroll with EMS", id: "enrollment") {
            EnrollmentWindow(model: model)
        }
        .commandsRemoved()

        Settings {
            SettingsView(model: model, service: delegate.service)
        }

        // Development aid: the menu content in a normal window (see FORTINO_DEBUG_OPEN).
        Window("Menu Preview", id: "menu-preview") {
            MenuView(model: model, service: delegate.service)
        }
        .commandsRemoved()
    }
}

/// File and Help menu items for the actions that used to crowd the menu-bar panel.
struct FortinoCommands: Commands {
    let model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some Commands {
        CommandGroup(replacing: .newItem) {
            Button("New Profile") {
                model.newProfileRequested = true
                show("profiles")
            }
            .keyboardShortcut("n")
            Button("Import from FortiClient…") { show("import") }
                .keyboardShortcut("i", modifiers: [.command, .shift])
            Divider()
            Button("Enroll with EMS Package…") { show("enrollment") }
        }
        CommandGroup(replacing: .help) {
            Button("Open Service Log in Console") { ServiceLog.openInConsole() }
            Button("Show Service Log in Finder") { ServiceLog.revealInFinder() }
        }
    }

    private func show(_ id: String) {
        openWindow(id: id)
        NSApp.activate(ignoringOtherApps: true)
    }
}

extension Notification.Name {
    static let fortinoShowProfiles = Notification.Name("org.fortino.showProfiles")
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    let service = VPNService()

    func applicationDidFinishLaunching(_ notification: Notification) {
        service.ensureRegistered()
        _ = OptionKey.shared
        // The Dock icon is shown only while an app window is open; otherwise Fortino lives in the
        // menu bar alone, like other menu-bar apps.
        let center = NotificationCenter.default
        center.addObserver(forName: NSWindow.didBecomeKeyNotification, object: nil, queue: .main) { note in
            MainActor.assumeIsolated {
                if let window = note.object as? NSWindow, Self.isAppWindow(window) {
                    NSApp.setActivationPolicy(.regular)
                }
            }
        }
        center.addObserver(forName: NSWindow.willCloseNotification, object: nil, queue: .main) { note in
            let closing = note.object as? NSWindow
            // The closing window is still listed as visible; check once it is gone.
            DispatchQueue.main.async {
                MainActor.assumeIsolated {
                    Self.hideFromDockIfNoWindows(except: closing)
                }
            }
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }

    /// Opening the app while it runs (Finder, Spotlight, `open`) shows the Profiles window when
    /// none is open.
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        let open = NSApp.windows.contains { Self.isAppWindow($0) && $0.isVisible }
        if !open { NotificationCenter.default.post(name: .fortinoShowProfiles, object: nil) }
        return false
    }

    /// "Quit" from the Dock closes the windows and leaves Fortino in the menu bar. Quit from the
    /// menu-bar menu, logout and shutdown still terminate.
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard Self.isQuitFromDock() else { return .terminateNow }
        for window in NSApp.windows where Self.isAppWindow(window) && window.isVisible {
            window.close()
        }
        NSApp.setActivationPolicy(.accessory)
        return .terminateCancel
    }

    /// Ordinary titled windows (Profiles, Import, …); not the menu-bar popover or panels.
    private static func isAppWindow(_ window: NSWindow) -> Bool {
        window.styleMask.contains(.titled) && !(window is NSPanel) && window.canBecomeMain
    }

    private static func hideFromDockIfNoWindows(except closing: NSWindow?) {
        let open = NSApp.windows.contains { $0 !== closing && isAppWindow($0) && $0.isVisible }
        if !open { NSApp.setActivationPolicy(.accessory) }
    }

    private static func isQuitFromDock() -> Bool {
        guard let event = NSAppleEventManager.shared().currentAppleEvent,
              event.eventClass == kCoreEventClass, event.eventID == kAEQuitApplication,
              let pid = event.attributeDescriptor(forKeyword: keySenderPIDAttr)?.int32Value
        else { return false }
        return NSRunningApplication(processIdentifier: pid)?.bundleIdentifier == "com.apple.dock"
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
