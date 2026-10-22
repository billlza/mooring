// swift-tools-version: 6.2
// SPDX-License-Identifier: GPL-3.0-or-later

// MooringKit: what Mooring.app knows of the console (design §15). It
// decodes the documents `mooringctl status --follow --json` prints, refusing
// any key or value it does not name, and runs that command; it never reads
// a secret or a daemon file (design §5.1).

import PackageDescription

let strict: [SwiftSetting] = [.treatAllWarnings(as: .error)]

let package = Package(
    name: "MooringKit",
    platforms: [.macOS(.v15)],
    products: [
        .library(name: "MooringKit", targets: ["MooringKit"])
    ],
    targets: [
        .target(name: "MooringKit", swiftSettings: strict),
        .testTarget(
            name: "MooringKitTests",
            dependencies: ["MooringKit"],
            swiftSettings: strict
        ),
    ],
    swiftLanguageModes: [.v6]
)
