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
        .target(name: "FortinoKit"),
        // Menu-bar app and profile window.
        .executableTarget(name: "Fortino", dependencies: ["FortinoKit"]),
        // Self-checks (the Command Line Tools have no XCTest).
        .executableTarget(name: "FortinoKitSelfTest", dependencies: ["FortinoKit"]),
    ]
)
