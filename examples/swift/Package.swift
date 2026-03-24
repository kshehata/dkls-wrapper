// swift-tools-version: 5.10
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "MobileTSSExample",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13),
    ],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
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
        .package(
            url: "https://github.com/ehn-dcc-development/base45-swift.git",
            from: "1.1.0"
        ),
        .package(path: "../../MobileTSS"),
    ],
    targets: [
        .target(
            name: "CLICore",
            dependencies: [
                .product(name: "MobileTSS", package: "MobileTSS"),
                .product(name: "MQTTNIO", package: "mqtt-nio"),
            ]
        ),
        .executableTarget(
            name: "CLIKeyGen",
            dependencies: [
                "CLICore",
                .product(name: "MobileTSS", package: "MobileTSS"),
                .product(name: "MQTTNIO", package: "mqtt-nio"),
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                .product(name: "base45-swift", package: "base45-swift"),
            ]
        ),
        .executableTarget(
            name: "CLISign",
            dependencies: [
                "CLICore",
                .product(name: "MobileTSS", package: "MobileTSS"),
                .product(name: "MQTTNIO", package: "mqtt-nio"),
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ]
        ),
    ]
)
