// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "OpenFortiClient",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "OpenFortiClient", targets: ["OpenFortiClient"]),
    ],
    targets: [
        // Protocol, socket client and validation; no UI.
        .target(name: "OFCKit"),
        // Menu-bar app and profile window.
        .executableTarget(name: "OpenFortiClient", dependencies: ["OFCKit"]),
        // Self-checks (the Command Line Tools have no XCTest).
        .executableTarget(name: "OFCKitSelfTest", dependencies: ["OFCKit"]),
    ]
)
