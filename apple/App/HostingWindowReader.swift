// SPDX-License-Identifier: GPL-3.0-or-later

// Hands a SwiftUI view's AppKit window to a callback whenever the view is
// put in one; SwiftUI has no API for it. The console window
// uses it so that ConsoleWindowFront (MooringKit) can raise it, through
// AppKitRaisableWindow.

import AppKit
import SwiftUI

struct HostingWindowReader: NSViewRepresentable {
    let attached: @MainActor (NSWindow) -> Void

    func makeNSView(context: Context) -> WindowReportingView {
        WindowReportingView(attached: attached)
    }

    func updateNSView(_ view: WindowReportingView, context: Context) {}
}

/// An empty view that reports each window it is moved into and takes no
/// events.
final class WindowReportingView: NSView {
    private let attached: @MainActor (NSWindow) -> Void

    init(attached: @escaping @MainActor (NSWindow) -> Void) {
        self.attached = attached
        super.init(frame: .zero)
    }

    required init?(coder: NSCoder) {
        nil
    }

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        if let window {
            attached(window)
        }
    }

    override func hitTest(_ point: NSPoint) -> NSView? {
        nil
    }
}
