// Renders the menu-bar template images from the shield outline
// (Resources/ShieldStatusBar.svg: an outer and an inner polygon, 1024 x 1024 viewBox).
// Run after changing the artwork; the PNGs are committed.
//
//   swift apps/macos/scripts/make-menubar-icons.swift apps/macos/Resources
//
// ShieldStatusBar           outline (disconnected)
// ShieldStatusBar-Filled    solid shield (connected)
// ShieldStatusBar-Half      outline, left half filled (connecting / disconnecting)
// ShieldStatusBar-Alert     outline with an exclamation mark (network recovery required)

import AppKit

let dir = URL(fileURLWithPath: CommandLine.arguments.dropFirst().first ?? ".")
let svg = try! String(contentsOf: dir.appendingPathComponent("ShieldStatusBar.svg"), encoding: .utf8)

// Parse `d` into polygons (the file only uses M, L and Z).
let d = svg.components(separatedBy: " d=\"")[1].components(separatedBy: "\"")[0]
var polys: [[CGPoint]] = []
for part in d.components(separatedBy: "M").dropFirst() {
    let pts = part.replacingOccurrences(of: "Z", with: "").components(separatedBy: "L").compactMap { s -> CGPoint? in
        let xy = s.trimmingCharacters(in: .whitespaces).split(separator: ",").compactMap { Double($0) }
        return xy.count == 2 ? CGPoint(x: xy[0], y: xy[1]) : nil
    }
    polys.append(pts)
}
precondition(polys.count == 2, "expected outer and inner outline")

func path(_ pts: [CGPoint]) -> NSBezierPath {
    let p = NSBezierPath()
    p.move(to: pts[0]); pts.dropFirst().forEach { p.line(to: $0) }; p.close()
    return p
}
let outer = path(polys[0]), inner = path(polys[1])

func outline() {
    let p = NSBezierPath(); p.append(outer); p.append(inner); p.windingRule = .evenOdd; p.fill()
}

let variants: [(String, () -> Void)] = [
    ("ShieldStatusBar", outline),
    ("ShieldStatusBar-Filled", { outer.fill() }),
    ("ShieldStatusBar-Half", {
        outline()
        NSGraphicsContext.saveGraphicsState()
        NSBezierPath(rect: CGRect(x: 0, y: 0, width: 512, height: 1024)).addClip()
        inner.fill()
        NSGraphicsContext.restoreGraphicsState()
    }),
    ("ShieldStatusBar-Alert", {
        outline()
        NSBezierPath(roundedRect: CGRect(x: 474, y: 300, width: 76, height: 320), xRadius: 38, yRadius: 38).fill()
        NSBezierPath(ovalIn: CGRect(x: 470, y: 672, width: 84, height: 84)).fill()
    }),
]

for (name, draw) in variants {
    for scale in [1, 2] {
        let px = 18 * scale
        let rep = NSBitmapImageRep(
            bitmapDataPlanes: nil, pixelsWide: px, pixelsHigh: px, bitsPerSample: 8, samplesPerPixel: 4,
            hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
        NSGraphicsContext.saveGraphicsState()
        let ctx = NSGraphicsContext(bitmapImageRep: rep)!
        NSGraphicsContext.current = ctx
        // SVG coordinates are y-down.
        ctx.cgContext.translateBy(x: 0, y: CGFloat(px))
        ctx.cgContext.scaleBy(x: CGFloat(px) / 1024, y: -CGFloat(px) / 1024)
        NSColor.black.setFill()
        draw()
        NSGraphicsContext.restoreGraphicsState()
        let file = scale == 1 ? "\(name).png" : "\(name)@2x.png"
        try! rep.representation(using: .png, properties: [:])!.write(to: dir.appendingPathComponent(file))
    }
}
