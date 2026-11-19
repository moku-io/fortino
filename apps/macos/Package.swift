// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "Fortino",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "Fortino", targets: ["Fortino"]),
    ],
    targets: [
        // Protocol, socket client and validation; no UI.
        .target(name: "OFCKit"),
        // Menu-bar app and profile window.
        .executableTarget(name: "Fortino", dependencies: ["OFCKit"]),
        // Self-checks (the Command Line Tools have no XCTest).
        .executableTarget(name: "OFCKitSelfTest", dependencies: ["OFCKit"]),
    ]
)
