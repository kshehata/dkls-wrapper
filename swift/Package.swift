// swift-tools-version:5.5
// The swift-tools-version declares the minimum version of Swift required to build this package.
// Swift Package: DKLSLib

import PackageDescription;

let package = Package(
    name: "DKLSLib",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15)
    ],
    products: [
        .library(
            name: "DKLSLib",
            targets: ["DKLSLib"]
        )
    ],
    dependencies: [ ],
    targets: [
        .binaryTarget(name: "dkls-ffi", path: "./dkls-ffi.xcframework"),
        .target(
            name: "DKLSLib",
            dependencies: [
                .target(name: "dkls-ffi")
            ]
        ),
        .testTarget(
            name: "DKLSLibTests",
            dependencies: ["DKLSLib"]
        ),
    ]
)