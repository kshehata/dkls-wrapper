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
            name: "MessagingCLI",
            targets: ["MessagingCLI"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/firebase/firebase-ios-sdk.git", from: "11.0.0")
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "DKLSLib",
            dependencies: ["libdkls-rs"]
        ),
        .executableTarget(
            name: "MessagingCLI",
            dependencies: [
                "DKLSLib",
                .product(name: "FirebaseAuth", package: "firebase-ios-sdk"),
                .product(name: "FirebaseFirestore", package: "firebase-ios-sdk"),
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
