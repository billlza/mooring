// SPDX-License-Identifier: GPL-3.0-or-later

// The console's AppKit window as ConsoleWindowFront (MooringKit) raises it.
// SwiftUI owns the window, so it is held weakly: a window SwiftUI has
// released is not on screen, and raising it does nothing.

import AppKit
import MooringKit

struct AppKitRaisableWindow: RaisableWindow {
    weak var window: NSWindow?

    var isVisible: Bool {
        window?.isVisible ?? false
    }

    func orderFrontRegardless() {
        window?.orderFrontRegardless()
    }
}
