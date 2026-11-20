// Fortino menu-bar app. Unprivileged: all VPN work happens in fortinod.

import AppKit
import FortinoKit
import SwiftUI

struct FortinoApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var model = AppModel()
    @StateObject private var service = VPNService()

    var body: some Scene {
        MenuBarExtra {
            MenuView(model: model, service: service)
        } label: {
            MenuBarLabel(model: model, service: service)
        }
        .menuBarExtraStyle(.window)

        Window("Profiles", id: "profiles") {
            ProfilesWindow(model: model)
        }
        Window("Import Profiles", id: "import") {
            ImportWindow(model: model)
        }
        // Development aid: the menu content in a normal window (see FORTINO_DEBUG_OPEN).
        Window("Menu Preview", id: "menu-preview") {
            MenuView(model: model, service: service)
        }
    }
}

/// Menu-bar icon. With `FORTINO_DEBUG_OPEN=profiles,menu-preview,import` set, also opens those
/// windows at launch (for development and screenshots).
struct MenuBarLabel: View {
    @ObservedObject var model: AppModel
    @ObservedObject var service: VPNService
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        StatusIcon(state: model.state)
            .task {
                // Registers the bundled VPN service on first launch (approval in Login Items).
                service.ensureRegistered()
                let ids = ProcessInfo.processInfo.environment["FORTINO_DEBUG_OPEN"]?
                    .split(separator: ",").map(String.init) ?? []
                for id in ids { openWindow(id: id) }
            }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        // Menu-bar app: no Dock icon.
        NSApp.setActivationPolicy(.accessory)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }
}

FortinoApp.main()
