// Menu-bar icon: the Fortino shield as template images (Resources/ShieldStatusBar*.png, drawn by
// scripts/make-menubar-icons.swift), so macOS tints them for light and dark menu bars.
// Outline when disconnected, filled when connected, half filled while connecting or disconnecting,
// an exclamation mark when network recovery is required. "In use" (another user's session) keeps
// an SF Symbol. Falls back to SF Symbols when the images are not in the bundle (e.g. `swift run`).

import AppKit
import FortinoKit
import SwiftUI

struct MenuBarIcon: View {
    let state: SessionState

    private static func load(_ name: String) -> NSImage? {
        guard let image = Bundle.main.image(forResource: name) else { return nil }
        image.isTemplate = true
        return image
    }
    private static let outline = load("ShieldStatusBar")
    private static let filled = load("ShieldStatusBar-Filled")
    private static let half = load("ShieldStatusBar-Half")
    private static let alert = load("ShieldStatusBar-Alert")

    var body: some View {
        icon.accessibilityLabel("Fortino: \(state.label)")
    }

    @ViewBuilder private var icon: some View {
        let (image, fallback): (NSImage?, String) = switch state {
        case .connected: (Self.filled, "lock.shield.fill")
        case .idle: (Self.outline, "lock.shield")
        case .recoveryRequired: (Self.alert, "exclamationmark.shield")
        case .inUse: (nil, "person.badge.shield.checkmark")
        default: (Self.half, "shield.lefthalf.filled")
        }
        if let image {
            Image(nsImage: image)
        } else {
            Image(systemName: fallback)
        }
    }
}
