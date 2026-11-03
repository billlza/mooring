// SPDX-License-Identifier: GPL-3.0-or-later

// Bringing the console window to the front when the operator chooses Open
// Console in the menu bar item (design §5.1). Mooring is an accessory app
// (LSUIElement), and since macOS 14 activation is cooperative: the app may
// ask to become active, and the system may decline while the operator works
// in another app. SwiftUI's `openWindow` shows the window but orders it
// front among Mooring's own windows only, so with activation declined it
// stays behind the active app's windows, and the operator chose the item
// again. On macOS 27.2 (2026-11-02), of four requests in a row the system
// honoured two, and a scratch app that never activates reproduced the
// window staying behind, in front once raised with `orderFrontRegardless`.
// The window is therefore raised above other apps' normal windows whether
// or not activation follows.
//
// What SwiftUI does on each path, measured there (its behaviour, not
// documented): when `openWindow` returns, a window that was open, closed or
// minimised is on screen again; a window it has never made appears up to
// 300 ms later, and the console's view moves into it once it is already on
// screen. So a request is served at once, or by the next window attached on
// screen within `requestLifetime`, a limit chosen at ten times that delay; a
// window arriving later stays where SwiftUI puts it, behind if activation
// was declined. A window that comes on screen without attaching is not
// raised: nothing observes it. Not handled, and not measured: a window on
// another Space, or behind a full-screen app, is raised where it is, out of
// the operator's sight. MooringKit holds the logic; the app hands it the
// AppKit window behind a value that holds the window weakly.

/// The console's window, as raising it needs it. A window that is gone is
/// not on screen.
@MainActor
public protocol RaisableWindow {
    /// Whether the window is on screen, even if other windows cover it.
    var isVisible: Bool { get }
    /// Moves the window in front of every window at its level, whether or
    /// not the app is active, without making it key.
    func orderFrontRegardless()
}

/// Raises the console window above other apps' normal windows when the
/// operator asks for it.
@MainActor
public final class ConsoleWindowFront {
    /// How long a request waits for the window SwiftUI is making: ten times
    /// the 300 ms it took on macOS 27.2.
    static let requestLifetime: Duration = .seconds(3)

    private let now: @MainActor () -> ContinuousClock.Instant
    /// The window the console's view is in.
    private var window: (any RaisableWindow)?
    /// Until when a request waits for a window to attach on screen.
    private var waitingUntil: ContinuousClock.Instant?

    /// Requests lapse by the continuous clock.
    public convenience init() {
        self.init(now: { ContinuousClock.now })
    }

    /// Requests lapse by `now`; the tests pass their own clock.
    init(now: @escaping @MainActor () -> ContinuousClock.Instant) {
        self.now = now
    }

    /// The console's view is now in `window`. A request waiting within its
    /// lifetime is served if the window is on screen; one past its lifetime
    /// lapses; with none, the window stays where SwiftUI put it, as at
    /// launch.
    public func attach(_ window: any RaisableWindow) {
        self.window = window
        guard let waitingUntil else {
            return
        }
        if now() > waitingUntil {
            self.waitingUntil = nil
        } else {
            raiseIfOnScreen()
        }
    }

    /// Opens the console with `open` (SwiftUI's `openWindow`), then raises
    /// its window if it is on screen, or waits for the window SwiftUI is
    /// making. A window that is not on screen is never shown here: only
    /// SwiftUI shows a window.
    public func bringToFront(opening open: () -> Void) {
        open()
        waitingUntil = now() + Self.requestLifetime
        raiseIfOnScreen()
    }

    private func raiseIfOnScreen() {
        guard let window, window.isVisible else {
            return
        }
        window.orderFrontRegardless()
        waitingUntil = nil
    }
}
