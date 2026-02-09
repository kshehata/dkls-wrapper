// swift-tools-version: 5.10
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "DKLSLib",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13),
    ],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "DKLSLib",
            targets: ["DKLSLib"]
        ),
        .executable(
            name: "dkg",
            targets: ["CLIKeyGen"]
        ),
        .executable(
            name: "sign",
            targets: ["CLISign"]
        ),
    ],
    dependencies: [
        .package(
            url: "https://github.com/swift-server-community/mqtt-nio.git",
            from: "2.12.1"
        ),
        .package(
            url: "https://github.com/apple/swift-argument-parser.git",
            from: "1.3.0"
        ),
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "DKLSLib",
            dependencies: ["libdkls-rs"]
        ),
        .target(
            name: "CLICore",
            dependencies: [
                "DKLSLib",
                .product(name: "MQTTNIO", package: "mqtt-nio"),
            ]
        ),
        .executableTarget(
            name: "CLIKeyGen",
            dependencies: [
                "CLICore",
                "DKLSLib",
                .product(name: "MQTTNIO", package: "mqtt-nio"),
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ]
        ),
        .executableTarget(
            name: "CLISign",
            dependencies: [
                "CLICore",
                "DKLSLib",
                .product(name: "MQTTNIO", package: "mqtt-nio"),
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ]
        ),
        .testTarget(
            name: "DKLSLibTests",
            dependencies: ["DKLSLib"]
        ),
        .binaryTarget(
            name: "libdkls-rs",
            path: "libdkls-rs.xcframework"
        ),
    ]
)
