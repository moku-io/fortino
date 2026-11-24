// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "Fortino",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "Fortino", targets: ["Fortino"]),
    ],
    dependencies: [
        // In-app updates: signed appcast and DMG from the GitHub releases.
        .package(url: "https://github.com/sparkle-project/Sparkle", from: "2.10.1"),
    ],
    targets: [
        // Protocol, socket client and validation; no UI.
        .target(name: "FortinoKit"),
        // Menu-bar app and profile window.
        .executableTarget(
            name: "Fortino",
            dependencies: ["FortinoKit", .product(name: "Sparkle", package: "Sparkle")],
            // bundle.sh puts Sparkle.framework in Contents/Frameworks.
            linkerSettings: [.unsafeFlags(["-Xlinker", "-rpath", "-Xlinker", "@executable_path/../Frameworks"])]
        ),
        // Self-checks (the Command Line Tools have no XCTest).
        .executableTarget(name: "FortinoKitSelfTest", dependencies: ["FortinoKit"]),
    ]
)
