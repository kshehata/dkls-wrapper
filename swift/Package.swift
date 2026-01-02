// swift-tools-version: 5.10
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "DKLSLib",
    platforms: [
        .macOS(.v10_15)
        // You can also specify other platforms like iOS, tvOS, watchOS
        // .iOS(.v13),
        // .tvOS(.v13),
        // .watchOS(.v6)
    ],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "DKLSLib",
            targets: ["DKLSLib"]
        ),
        .executable(
            name: "DKLSCLI",
            targets: ["DKLSCLI"]
        ),
    ],
    dependencies: [
        .package(
            url: "https://github.com/swift-server-community/mqtt-nio.git",
            from: "2.12.1"
        )
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "DKLSLib",
            dependencies: ["libdkls-rs"]
        ),
        .executableTarget(
            name: "DKLSCLI",
            dependencies: [
                "DKLSLib",
                .product(name: "MQTTNIO", package: "mqtt-nio"),
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
