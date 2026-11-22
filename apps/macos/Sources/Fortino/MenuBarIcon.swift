// Menu-bar icon: the Fortino shield (Resources/ShieldStatusBar*.png, a template image so macOS
// tints it for light and dark menu bars). Full strength when connected, dimmed otherwise; states
// that need attention keep an SF Symbol badge. Falls back to SF Symbols when the image is not in
// the bundle (e.g. `swift run`).

import AppKit
import FortinoKit
import SwiftUI

struct MenuBarIcon: View {
    let state: SessionState

    private static let shield: NSImage? = {
        guard let image = Bundle.main.image(forResource: "ShieldStatusBar") else { return nil }
        image.isTemplate = true
        image.size = NSSize(width: 18, height: 18)
        return image
    }()

    var body: some View {
        Group {
            switch state {
            case .recoveryRequired:
                Image(systemName: "exclamationmark.shield")
            case .inUse:
                Image(systemName: "person.badge.shield.checkmark")
            default:
                if let shield = Self.shield {
                    Image(nsImage: dimmed(shield))
                } else if case .connected = state {
                    Image(systemName: "lock.shield.fill")
                } else {
                    Image(systemName: "lock.shield")
                }
            }
        }
        .accessibilityLabel("Fortino: \(state.label)")
    }

    /// MenuBarExtra labels ignore SwiftUI opacity, so dimming is baked into the template's alpha.
    private func dimmed(_ image: NSImage) -> NSImage {
        if case .connected = state { return image }
        let out = NSImage(size: image.size, flipped: false) { rect in
            image.draw(in: rect, from: .zero, operation: .sourceOver, fraction: 0.55)
            return true
        }
        out.isTemplate = true
        return out
    }
}
