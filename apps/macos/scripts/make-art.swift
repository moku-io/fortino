// Draws Fortino's app icon and the disk-image background at build time (no binary assets in the
// repository). Original artwork from standard SF Symbols; not derived from any vendor's design.
//
//   swift apps/macos/scripts/make-art.swift OUT_DIR
//
// Writes OUT_DIR/AppIcon.icns and OUT_DIR/dmg-background.tiff (1x + 2x).

import AppKit

let out = URL(fileURLWithPath: CommandLine.arguments.dropFirst().first ?? ".")
try? FileManager.default.createDirectory(at: out, withIntermediateDirectories: true)

/// Renders `draw` into a bitmap of `size` points at `scale` and returns PNG data.
func render(_ size: CGSize, scale: CGFloat, _ draw: (CGRect) -> Void) -> Data {
    let rep = NSBitmapImageRep(
        bitmapDataPlanes: nil, pixelsWide: Int(size.width * scale), pixelsHigh: Int(size.height * scale),
        bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
        colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    rep.size = size
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    draw(CGRect(origin: .zero, size: size))
    NSGraphicsContext.restoreGraphicsState()
    return rep.representation(using: .png, properties: [:])!
}

func symbol(_ name: String, pointSize: CGFloat, weight: NSFont.Weight, colors: [NSColor]) -> NSImage {
    let cfg = NSImage.SymbolConfiguration(pointSize: pointSize, weight: weight)
        .applying(.init(paletteColors: colors))
    return NSImage(systemSymbolName: name, accessibilityDescription: nil)!.withSymbolConfiguration(cfg)!
}

func color(_ hex: UInt32, _ alpha: CGFloat = 1) -> NSColor {
    NSColor(srgbRed: CGFloat(hex >> 16 & 0xff) / 255, green: CGFloat(hex >> 8 & 0xff) / 255,
            blue: CGFloat(hex & 0xff) / 255, alpha: alpha)
}

// MARK: App icon: a white shield with a lock on a deep-blue rounded square.

func drawIcon(_ r: CGRect) {
    let s = r.width / 1024
    let tile = CGRect(x: 100 * s, y: 100 * s, width: 824 * s, height: 824 * s)
    let path = NSBezierPath(roundedRect: tile, xRadius: 185 * s, yRadius: 185 * s)

    NSGraphicsContext.saveGraphicsState()
    let shadow = NSShadow()
    shadow.shadowColor = .black.withAlphaComponent(0.3)
    shadow.shadowBlurRadius = 24 * s
    shadow.shadowOffset = CGSize(width: 0, height: -10 * s)
    shadow.set()
    color(0x1D4ED8).setFill()
    path.fill()
    NSGraphicsContext.restoreGraphicsState()

    NSGradient(colors: [color(0x3B82F6), color(0x1E3A8A)])!.draw(in: path, angle: -90)
    // Soft highlight on the upper half.
    NSGraphicsContext.saveGraphicsState()
    path.addClip()
    NSGradient(colors: [.white.withAlphaComponent(0.18), .white.withAlphaComponent(0)])!
        .draw(in: CGRect(x: tile.minX, y: tile.midY, width: tile.width, height: tile.height / 2), angle: -90)
    NSGraphicsContext.restoreGraphicsState()

    let glyph = symbol("lock.shield.fill", pointSize: 470 * s, weight: .regular,
                       colors: [color(0x1E40AF), .white])
    let g = glyph.size
    glyph.draw(in: CGRect(x: tile.midX - g.width / 2, y: tile.midY - g.height / 2 - 6 * s,
                          width: g.width, height: g.height))
}

let iconset = out.appendingPathComponent("AppIcon.iconset")
try? FileManager.default.removeItem(at: iconset)
try! FileManager.default.createDirectory(at: iconset, withIntermediateDirectories: true)
for pt in [16, 32, 128, 256, 512] {
    for scale in [1, 2] {
        let name = scale == 1 ? "icon_\(pt)x\(pt).png" : "icon_\(pt)x\(pt)@2x.png"
        let data = render(CGSize(width: pt, height: pt), scale: CGFloat(scale), drawIcon)
        try! data.write(to: iconset.appendingPathComponent(name))
    }
}

// MARK: Disk-image background: 640 x 400 points, app on the left, Applications on the right.
// Icon centres (Finder coordinates, origin top left): (170, 190) and (470, 190).

func drawBackground(_ r: CGRect) {
    NSGradient(colors: [color(0xF8FAFC), color(0xE2E8F0)])!.draw(in: r, angle: -90)

    // Arrow between the two icons (y = 400 - 190 in drawing coordinates).
    let y: CGFloat = 210
    let arrow = NSBezierPath()
    arrow.move(to: CGPoint(x: 262, y: y))
    arrow.line(to: CGPoint(x: 370, y: y))
    arrow.lineWidth = 6
    arrow.lineCapStyle = .round
    color(0x3B82F6, 0.85).setStroke()
    arrow.stroke()
    let head = NSBezierPath()
    head.move(to: CGPoint(x: 352, y: y + 18))
    head.line(to: CGPoint(x: 376, y: y))
    head.line(to: CGPoint(x: 352, y: y - 18))
    head.lineWidth = 6
    head.lineCapStyle = .round
    head.lineJoinStyle = .round
    head.stroke()

    let title = NSAttributedString(string: "Install Fortino", attributes: [
        .font: NSFont.systemFont(ofSize: 22, weight: .semibold),
        .foregroundColor: color(0x0F172A),
    ])
    title.draw(at: CGPoint(x: (r.width - title.size().width) / 2, y: 340))
    let hint = NSAttributedString(string: "Drag Fortino to the Applications folder, then open it.", attributes: [
        .font: NSFont.systemFont(ofSize: 13),
        .foregroundColor: color(0x475569),
    ])
    hint.draw(at: CGPoint(x: (r.width - hint.size().width) / 2, y: 52))
}

let bg = CGSize(width: 640, height: 400)
try! render(bg, scale: 1, drawBackground).write(to: out.appendingPathComponent("bg.png"))
try! render(bg, scale: 2, drawBackground).write(to: out.appendingPathComponent("bg@2x.png"))
