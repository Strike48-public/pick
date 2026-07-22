// swift-tools-version: 5.8
import PackageDescription

let package = Package(
    name: "PickShared",
    products: [
        .library(
            name: "PickShared",
            targets: ["PickShared"]
        )
    ],
    targets: [
        .target(
            name: "PickShared",
            dependencies: ["Serde"]
        ),
        .target(
            name: "Serde",
            dependencies: []
        ),
    ]
)
