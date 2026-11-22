// Renders Resources/AppIcon.iconset from Resources/AppIcon.svg (full-bleed artwork on a 1024 canvas).
// The artwork is placed on the macOS icon grid: an 824 x 824 body centered on the 1024 canvas with a
// soft drop shadow, so the icon matches the size of other apps in the Dock and Finder.
// Run after changing the artwork; the PNGs are committed.
//
//   swift apps/macos/scripts/make-app-icon.swift apps/macos/Resources

import AppKit

let dir = URL(fileURLWithPath: CommandLine.arguments.dropFirst().first ?? ".")
guard let art = NSImage(contentsOf: dir.appendingPathComponent("AppIcon.svg")) else {
    fatalError("cannot load AppIcon.svg")
}
let iconset = dir.appendingPathComponent("AppIcon.iconset")
try FileManager.default.createDirectory(at: iconset, withIntermediateDirectories: true)

func render(px: Int) -> Data {
    let rep = NSBitmapImageRep(
        bitmapDataPlanes: nil, pixelsWide: px, pixelsHigh: px, bitsPerSample: 8, samplesPerPixel: 4,
        hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    NSGraphicsContext.saveGraphicsState()
    let ctx = NSGraphicsContext(bitmapImageRep: rep)!
    NSGraphicsContext.current = ctx
    ctx.imageInterpolation = .high
    let k = CGFloat(px) / 1024
    ctx.cgContext.scaleBy(x: k, y: k)
    // Shadow is skipped at the smallest sizes, where it only muddies the edge.
    if px >= 64 {
        ctx.cgContext.setShadow(
            offset: CGSize(width: 0, height: -10 * k), blur: 24 * k,
            color: NSColor.black.withAlphaComponent(0.3).cgColor)
    }
    art.draw(in: CGRect(x: 100, y: 100, width: 824, height: 824))
    NSGraphicsContext.restoreGraphicsState()
    return rep.representation(using: .png, properties: [:])!
}

for base in [16, 32, 128, 256, 512] {
    for scale in [1, 2] {
        let name = scale == 1 ? "icon_\(base)x\(base).png" : "icon_\(base)x\(base)@2x.png"
        try render(px: base * scale).write(to: iconset.appendingPathComponent(name))
    }
}
