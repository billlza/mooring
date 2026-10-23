// SPDX-License-Identifier: GPL-3.0-or-later

// The power helper's logic (design §5.1, §10.3), apart from IOKit: it
// holds the two assertions when the daemon says so, reports the power
// source and its changes, numbers each sleep macOS announces and holds it
// until the daemon answers (or `allowSleepAfter` passes), reports wakes,
// and at the end of its input releases everything and lets any held sleep
// proceed. The `mooring-power` tool runs it over IOKit; the tests run it
// over a recorder.

import Foundation

/// An IOKit call that failed, with the status it returned.
public struct PowerSystemError: Error, Equatable, Sendable {
    public let call: String
    public let status: Int32

    public init(call: String, status: Int32) {
        self.call = call
        self.status = status
    }
}

/// What the helper does to macOS.
@MainActor
public protocol PowerSystem: AnyObject {
    /// The source macOS draws power from now.
    func readPowerSource() throws(PowerSystemError) -> PowerSourceValue
    /// Holds `NetworkClientActive` and `PreventUserIdleSystemSleep`, both
    /// or neither.
    func holdAssertions() throws(PowerSystemError)
    /// Releases them.
    func releaseAssertions()
    /// Lets the sleep IOKit announced as `token` proceed.
    func allowSleep(token: Int)
}

@MainActor
public final class PowerHelper {
    private let system: any PowerSystem
    private let emit: (HelperEvent) -> Void
    private let report: (String) -> Void
    private var held = false
    private var source: PowerSourceValue?
    private var nextSleep: UInt64 = 1
    /// The sleeps held for the daemon, by number: IOKit's token for each.
    private var sleeps: [UInt64: Int] = [:]

    /// A helper over `system` that writes its events with `emit` and its
    /// diagnostics (the daemon's log) with `report`.
    public init(
        system: any PowerSystem,
        emit: @escaping (HelperEvent) -> Void,
        report: @escaping (String) -> Void
    ) {
        self.system = system
        self.emit = emit
        self.report = report
    }

    /// Whether the assertions are held.
    public var holding: Bool { held }

    /// The first report: the power source. A source that cannot be read
    /// fails the start: the daemon then has none to report.
    public func start() throws(PowerSystemError) {
        let now = try system.readPowerSource()
        source = now
        emit(.powerSource(now))
    }

    /// One command from the daemon. An answer for a sleep that is no longer
    /// held (it timed out) changes nothing.
    public func handle(_ command: HelperCommand) {
        switch command {
        case .hold(true):
            if !held {
                do {
                    try system.holdAssertions()
                    held = true
                } catch {
                    report("mooring-power: \(error.call) failed with \(error.status)")
                }
            }
            emit(.assertions(held: held))
        case .hold(false):
            if held {
                system.releaseAssertions()
                held = false
            }
            emit(.assertions(held: false))
        case .allowSleep(let id):
            if let token = sleeps.removeValue(forKey: id) {
                system.allowSleep(token: token)
            }
        }
    }

    /// macOS will sleep, as IOKit's `token`: the sleep is held for the
    /// daemon. Returns its number, for the timeout the tool schedules.
    public func willSleep(token: Int) -> UInt64 {
        let id = nextSleep
        nextSleep += 1
        sleeps[id] = token
        emit(.willSleep(id: id))
        return id
    }

    /// The daemon did not answer the sleep `id` in time: it proceeds.
    public func sleepTimedOut(id: UInt64) {
        if let token = sleeps.removeValue(forKey: id) {
            report("mooring-power: the daemon did not answer sleep \(id); it proceeds")
            system.allowSleep(token: token)
        }
    }

    /// macOS woke.
    public func didWake() {
        emit(.didWake)
    }

    /// The power source may have changed: reported when it did. A read
    /// that fails is reported to the log, and the last source stands.
    public func powerSourceChanged() {
        do {
            let now = try system.readPowerSource()
            if now != source {
                source = now
                emit(.powerSource(now))
            }
        } catch {
            report("mooring-power: \(error.call) failed with \(error.status)")
        }
    }

    /// The daemon's end (its pipe closed): the assertions are released and
    /// every held sleep proceeds.
    public func inputEnded() {
        if held {
            system.releaseAssertions()
            held = false
        }
        for token in sleeps.values {
            system.allowSleep(token: token)
        }
        sleeps.removeAll()
    }
}
