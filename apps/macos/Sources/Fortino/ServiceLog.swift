// The VPN service's log file, written by launchd from fortinod's stderr (StandardErrorPath in
// Resources/org.fortino.fortinod.plist). Readable by every user; the service redacts secrets
// before writing.

import AppKit

enum ServiceLog {
    static let url = URL(fileURLWithPath: "/var/log/fortinod.log")

    /// False before the service first ran, and with a development daemon that logs elsewhere.
    static var exists: Bool { FileManager.default.isReadableFile(atPath: url.path) }

    /// Opens the log in Console, which follows new lines as they are written.
    static func openInConsole() {
        guard exists else { return }
        if let console = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "com.apple.Console") {
            NSWorkspace.shared.open([url], withApplicationAt: console, configuration: NSWorkspace.OpenConfiguration())
        } else {
            NSWorkspace.shared.open(url)
        }
    }

    /// Opens /var/log in Finder with the log selected.
    static func revealInFinder() {
        guard exists else { return }
        NSWorkspace.shared.activateFileViewerSelecting([url])
    }

    static let missingHelp = "The VPN service hasn't written a log on this Mac yet."
}

/// Tracks the Option key so the menu-bar panel can show its troubleshooting items, like the
/// system's Wi-Fi menu. Read when a window becomes key (the panel opening) and updated live while
/// the panel is open.
@MainActor
final class OptionKey: ObservableObject {
    static let shared = OptionKey()
    @Published private(set) var isDown = false

    private init() {
        NSEvent.addLocalMonitorForEvents(matching: .flagsChanged) { [weak self] event in
            let down = event.modifierFlags.contains(.option)
            MainActor.assumeIsolated { self?.set(down) }
            return event
        }
        NotificationCenter.default.addObserver(
            forName: NSWindow.didBecomeKeyNotification, object: nil, queue: .main
        ) { [weak self] _ in
            let down = NSEvent.modifierFlags.contains(.option)
            MainActor.assumeIsolated { self?.set(down) }
        }
    }

    private func set(_ down: Bool) {
        if isDown != down { isDown = down }
    }
}
