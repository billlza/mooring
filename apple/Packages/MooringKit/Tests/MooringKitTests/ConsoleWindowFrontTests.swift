// SPDX-License-Identifier: GPL-3.0-or-later

// Raising the console window over a recorder and a clock the tests move:
// the window SwiftUI already shows, the one it shows again, and the one it
// is still making, each raised once per request and only after `openWindow`;
// a window attached without a request, not on screen, gone, or after the
// request's lifetime, is left alone.

import Testing

@testable import MooringKit

/// What happened, in order.
@MainActor
private final class Record {
    var entries: [String] = []
}

/// A window that records being raised.
@MainActor
private final class StandInWindow: RaisableWindow {
    let name: String
    var isVisible: Bool
    private let record: Record

    init(_ name: String, visible: Bool, record: Record) {
        self.name = name
        self.isVisible = visible
        self.record = record
    }

    func orderFrontRegardless() {
        record.entries.append("raise \(name)")
    }
}

/// The time the tests set.
@MainActor
private final class ManualClock {
    private(set) var now = ContinuousClock.now

    func advance(by duration: Duration) {
        now = now.advanced(by: duration)
    }
}

@MainActor
@Suite struct ConsoleWindowFrontTests {
    private let record = Record()
    private let clock: ManualClock
    private let front: ConsoleWindowFront

    init() {
        let clock = ManualClock()
        self.clock = clock
        front = ConsoleWindowFront(now: { clock.now })
    }

    private func open() {
        record.entries.append("open")
    }

    private func window(_ name: String, visible: Bool) -> StandInWindow {
        StandInWindow(name, visible: visible, record: record)
    }

    @Test func aWindowOnScreenIsRaisedAfterItIsOpened() {
        front.attach(window("console", visible: true))
        front.bringToFront(opening: open)
        #expect(record.entries == ["open", "raise console"])
    }

    /// A closed or minimised window is on screen again when `openWindow`
    /// returns.
    @Test func aWindowThatOpeningShowsAgainIsRaised() {
        let console = window("console", visible: false)
        front.attach(console)
        front.bringToFront {
            open()
            console.isVisible = true
        }
        #expect(record.entries == ["open", "raise console"])
    }

    @Test func aWindowIsRaisedAgainAtEveryRequest() {
        front.attach(window("console", visible: true))
        front.bringToFront(opening: open)
        front.bringToFront(opening: open)
        #expect(record.entries == ["open", "raise console", "open", "raise console"])
    }

    @Test func aWindowStillBeingMadeIsRaisedWhenItAttaches() {
        front.bringToFront(opening: open)
        #expect(record.entries == ["open"])
        front.attach(window("console", visible: true))
        #expect(record.entries == ["open", "raise console"])
    }

    @Test func twoRequestsBeforeTheWindowAttachesRaiseItOnce() {
        front.bringToFront(opening: open)
        front.bringToFront(opening: open)
        front.attach(window("console", visible: true))
        #expect(record.entries == ["open", "open", "raise console"])
    }

    @Test func aWindowAttachedWhileOpeningIsRaisedOnceAfterwards() {
        let console = window("console", visible: true)
        front.bringToFront {
            open()
            front.attach(console)
        }
        #expect(record.entries == ["open", "raise console"])
    }

    @Test func aRequestIsServedOnce() {
        front.bringToFront(opening: open)
        front.attach(window("first", visible: true))
        front.attach(window("second", visible: true))
        #expect(record.entries == ["open", "raise first"])
    }

    @Test func aRequestServedAtOnceLeavesNothingWaiting() {
        front.attach(window("console", visible: true))
        front.bringToFront(opening: open)
        front.attach(window("later", visible: true))
        #expect(record.entries == ["open", "raise console"])
    }

    @Test func aWindowAttachedWithoutARequestIsLeftWhereItIs() {
        front.attach(window("console", visible: true))
        #expect(record.entries == [])
    }

    @Test func aRequestWaitsForTheNextWindowAttachedOnScreen() {
        front.bringToFront(opening: open)
        front.attach(window("hidden", visible: false))
        #expect(record.entries == ["open"])
        front.attach(window("shown", visible: true))
        #expect(record.entries == ["open", "raise shown"])
    }

    @Test func aWindowComingOnScreenWithoutAttachingIsNotRaised() {
        front.bringToFront(opening: open)
        let console = window("console", visible: false)
        front.attach(console)
        console.isVisible = true
        #expect(record.entries == ["open"])
    }

    @Test func aWindowNotOnScreenIsNeverShown() {
        front.attach(window("console", visible: false))
        front.bringToFront(opening: open)
        #expect(record.entries == ["open"])
    }

    /// The app's window value reports a window SwiftUI released as not on
    /// screen.
    @Test func aWindowThatIsGoneIsNotRaisedAndTheRequestWaits() {
        let console = window("console", visible: true)
        front.attach(console)
        console.isVisible = false
        front.bringToFront(opening: open)
        #expect(record.entries == ["open"])
        front.attach(window("remade", visible: true))
        #expect(record.entries == ["open", "raise remade"])
    }

    @Test func aRequestIsServedUpToTheEndOfItsLifetime() {
        front.bringToFront(opening: open)
        clock.advance(by: ConsoleWindowFront.requestLifetime)
        front.attach(window("console", visible: true))
        #expect(record.entries == ["open", "raise console"])
    }

    @Test func aRequestLapsesAfterItsLifetime() {
        front.bringToFront(opening: open)
        clock.advance(by: ConsoleWindowFront.requestLifetime + .milliseconds(1))
        front.attach(window("late", visible: true))
        // Moving the clock back shows the request is gone, not only late.
        clock.advance(by: .seconds(-10))
        front.attach(window("later", visible: true))
        #expect(record.entries == ["open"])
    }

    /// The app's own front reads the continuous clock; a window that
    /// attaches at once is within the request's lifetime on it.
    @Test func onTheContinuousClockAPromptAttachServesTheRequest() {
        let appFront = ConsoleWindowFront()
        appFront.bringToFront(opening: open)
        appFront.attach(window("console", visible: true))
        #expect(record.entries == ["open", "raise console"])
    }

    @Test func aNewRequestStartsANewLifetime() {
        front.bringToFront(opening: open)
        clock.advance(by: .seconds(2))
        front.bringToFront(opening: open)
        clock.advance(by: .seconds(2))
        front.attach(window("console", visible: true))
        #expect(record.entries == ["open", "open", "raise console"])
    }
}
