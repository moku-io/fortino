// OpenFortiClient menu-bar app. Unprivileged: all VPN work happens in ofcd.

import AppKit
import OFCKit
import SwiftUI

struct OpenFortiClientApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var model = AppModel()

    var body: some Scene {
        MenuBarExtra {
            MenuView(model: model)
        } label: {
            MenuBarLabel(model: model)
        }
        .menuBarExtraStyle(.window)

        Window("Profiles", id: "profiles") {
            ProfilesWindow(model: model)
        }
        Window("Import Profiles", id: "import") {
            ImportWindow(model: model)
        }
        // Development aid: the menu content in a normal window (see OFC_DEBUG_OPEN).
        Window("Menu Preview", id: "menu-preview") {
            MenuView(model: model)
        }
    }
}

/// Menu-bar icon. With `OFC_DEBUG_OPEN=profiles,menu-preview,import` set, also opens those
/// windows at launch (for development and screenshots).
struct MenuBarLabel: View {
    @ObservedObject var model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        StatusIcon(state: model.state)
            .task {
                let ids = ProcessInfo.processInfo.environment["OFC_DEBUG_OPEN"]?
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

OpenFortiClientApp.main()
