// swift-tools-version:5.5
// The swift-tools-version declares the minimum version of Swift required to build this package.
// Swift Package: MobileTSS

import PackageDescription;

let package = Package(
    name: "MobileTSS",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15)
    ],
    products: [
        .library(
            name: "MobileTSS",
            targets: ["MobileTSS"]
        )
    ],
    dependencies: [ ],
    targets: [
        .binaryTarget(name: "mobile-tss-ffi", path: "./mobile-tss-ffi.xcframework"),
        .target(
            name: "MobileTSS",
            dependencies: [
                .target(name: "mobile-tss-ffi")
            ]
        ),
        .testTarget(
            name: "MobileTSSTests",
            dependencies: ["MobileTSS"]
        ),
    ]
)