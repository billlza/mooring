// swift-tools-version: 6.2
// SPDX-License-Identifier: GPL-3.0-or-later

// MooringKit: what Mooring.app knows of the console (design §15). It
// decodes the documents `mooringctl status --follow --json` prints, refusing
// any key or value it does not name, and runs that command; it never reads
// a secret or a daemon file (design §5.1). It also holds the app's own
// logic apart from AppKit and ServiceManagement, such as raising the
// console window (ConsoleWindowFront) and carrying the start of the app's
// two launch agents through after a new build (LaunchRound), so that the
// logic is tested.
//
// MooringPower: the power helper's protocol and its logic, apart from
// IOKit (design §5.1, §10.3); the `mooring-power` tool (apple/Power) runs
// it over IOKit.

import PackageDescription

let strict: [SwiftSetting] = [.treatAllWarnings(as: .error)]

let package = Package(
    name: "MooringKit",
    platforms: [.macOS(.v15)],
    products: [
        .library(name: "MooringKit", targets: ["MooringKit"]),
        .library(name: "MooringPower", targets: ["MooringPower"]),
    ],
    targets: [
        .target(name: "MooringKit", swiftSettings: strict),
        .testTarget(
            name: "MooringKitTests",
            dependencies: ["MooringKit"],
            swiftSettings: strict
        ),
        .target(name: "MooringPower", swiftSettings: strict),
        .testTarget(
            name: "MooringPowerTests",
            dependencies: ["MooringPower"],
            swiftSettings: strict
        ),
    ],
    swiftLanguageModes: [.v6]
)
