// swift-tools-version: 5.4

import PackageDescription

let package = Package(
    name: "unfair-swift",
    platforms: [
        .macOS(.v10_15),
    ],
    products: [
        .library(name: "UnfairKit", targets: ["UnfairKit"]),
        .executable(name: "unfair-swift", targets: ["UnfairCLI"]),
    ],
    dependencies: [
        .package(url: "https://github.com/weichsel/ZIPFoundation.git", .exact("0.9.19")),
        .package(url: "https://github.com/apple/swift-argument-parser.git", .upToNextMinor(from: "1.0.0")),
    ],
    targets: [
        .target(
            name: "UnfairKit",
            dependencies: [
                .product(name: "ZIPFoundation", package: "ZIPFoundation"),
            ]
        ),
        .executableTarget(
            name: "UnfairCLI",
            dependencies: [
                "UnfairKit",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ]
        ),
    ]
)
