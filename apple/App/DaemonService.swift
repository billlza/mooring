// SPDX-License-Identifier: GPL-3.0-or-later

// The daemon as a login item (design §5.1, M7): Mooring.app registers the
// LaunchAgent its bundle carries (`Contents/Library/LaunchAgents/
// com.bill.mooring.daemon.plist`) with SMAppService, so launchd runs the
// bundle's `mooringctl daemon` at login and keeps it running. Beside it,
// the app registers the nightly apply job (`com.bill.mooring.apply.plist`,
// design §13.6), which launchd runs every hour at minute 20 as
// `mooringctl apply --pending`; starting and stopping the daemon starts and
// stops both. When macOS wants the operator's approval first, the console
// says so (`AgentNotEnabled`) and opens Login Items. The app itself can be
// a login item too, so the console opens at login.
//
// SMAppService tells whether an agent is registered, not whether macOS
// lets its program start: after a new build macOS refuses both until its
// records are replaced. So a start is followed by a round (MooringKit's
// `LaunchRound`) that reads launchd's records with `/bin/launchctl` and
// carries the start through, and outside a round the records are read for
// what they ask of the operator. This file is the round's host and nothing
// more: what to do is decided in MooringKit, where it is tested.

import MooringKit
import Observation
import ServiceManagement

/// The daemon's registration, as the app shows it.
enum DaemonRegistration: Equatable {
    /// Registered and allowed: launchd runs the daemon.
    case enabled
    /// Registered, but macOS waits for the operator's approval in Login
    /// Items (`AgentNotEnabled`, design §5.1).
    case requiresApproval
    /// Not registered: the daemon does not run at login.
    case notRegistered

    init(_ status: SMAppService.Status) {
        switch status {
        case .enabled: self = .enabled
        case .requiresApproval: self = .requiresApproval
        // Measured 2026-10-23 on macOS 27.0: a never-registered agent
        // reports `.notFound`, one unregistered since `.notRegistered`.
        case .notRegistered, .notFound: self = .notRegistered
        @unknown default: self = .notRegistered
        }
    }
}

@MainActor
@Observable
final class DaemonService {
    /// The daemon's plist in the app's bundle, and its label for launchd.
    static let plistName = "com.bill.mooring.daemon.plist"
    static let label = "com.bill.mooring.daemon"
    /// The nightly apply job's plist in the app's bundle, and its label.
    static let applyPlistName = "com.bill.mooring.apply.plist"
    static let applyLabel = "com.bill.mooring.apply"
    /// launchd's records change without the app, as when macOS refuses the
    /// apply job at its own hour: they are read again this often.
    static let recordsInterval: Duration = .seconds(300)

    private(set) var daemon: DaemonRegistration
    private(set) var applyJob: DaemonRegistration
    private(set) var openAtLogin: Bool
    /// What the last change failed with, in the system's words.
    private(set) var failure: String?
    /// What the round that carries a start through is doing, while one
    /// runs.
    private(set) var round: LaunchRoundPhase?
    /// Why the last round did not get there, until another begins or the
    /// daemon is stopped.
    private(set) var roundFailure: LaunchRoundFailure?
    /// What launchd's records asked of the operator when they were last
    /// read outside a round.
    private(set) var attention: LaunchAttention = .nothing
    /// What kept that reading from telling whether macOS lets the agents
    /// start.
    private(set) var untold: [LaunchRoundFailure] = []

    private let agent = SMAppService.agent(plistName: DaemonService.plistName)
    private let applyAgent = SMAppService.agent(plistName: DaemonService.applyPlistName)
    private let launchctl = Launchctl()
    private var roundTask: Task<Void, Never>?
    private var reading: Task<Void, Never>?
    /// How many rounds have begun: a reading of launchd's records that one
    /// overtook is of before it.
    private var rounds = 0

    init() {
        daemon = DaemonRegistration(agent.status)
        applyJob = DaemonRegistration(applyAgent.status)
        openAtLogin = SMAppService.mainApp.status == .enabled
        // The service lives as long as the app, and this task with it; the
        // wait throws only for a cancelled task, which this one never is.
        Task {
            while true {
                readRecords()
                do {
                    try await Task.sleep(for: Self.recordsInterval)
                } catch {
                    return
                }
            }
        }
    }

    /// Reads the registrations again, since Login Items may have changed
    /// them, and launchd's records of them. A round changes the agents'
    /// registrations itself, and the screen shows the round: they are read
    /// again when it ends.
    func refresh() {
        openAtLogin = SMAppService.mainApp.status == .enabled
        guard roundTask == nil else {
            return
        }
        daemon = DaemonRegistration(agent.status)
        applyJob = DaemonRegistration(applyAgent.status)
        readRecords()
    }

    /// Registers the daemon, then the apply job, whichever is not
    /// registered: launchd starts the daemon now and at every login, and
    /// the job every hour at minute 20. Then the start is carried through.
    /// With both registered already, as when macOS refuses one or a round
    /// did not get there, it is the carrying through alone.
    func start() {
        guard roundTask == nil else {
            return
        }
        change(registerAgents)
        if failure == nil {
            carryThrough()
        }
    }

    /// Carries the start of the registered agents through from whatever
    /// launchd's records show: nothing more when macOS lets them start,
    /// the round of a new build when it refuses the daemon, the apply
    /// job's repair when it refuses only the job. Not while macOS waits
    /// for the operator's approval: the banner asks for that.
    private func carryThrough() {
        guard daemon == .enabled, applyJob == .enabled else {
            return
        }
        roundFailure = nil
        attention = .nothing
        untold = []
        round = .starting
        rounds += 1
        roundTask = Task {
            let outcome = await LaunchRound.run(on: self)
            // A stop ended it, and has said what there is to say.
            guard !Task.isCancelled else {
                return
            }
            roundTask = nil
            round = nil
            if case .failed(let failure) = outcome {
                roundFailure = failure
            }
            refresh()
        }
    }

    /// Unregisters the daemon, then the apply job: launchd stops the
    /// daemon, and starts neither again. A round under way ends.
    func stop() {
        roundTask?.cancel()
        roundTask = nil
        round = nil
        roundFailure = nil
        change(unregisterAgents)
    }

    /// Makes the app a login item, or stops it being one.
    func setOpenAtLogin(_ open: Bool) {
        change {
            if open {
                try SMAppService.mainApp.register()
            } else {
                try SMAppService.mainApp.unregister()
            }
        }
    }

    /// Opens System Settings at Login Items, where the operator approves
    /// the daemon.
    func openLoginItems() {
        SMAppService.openSystemSettingsLoginItems()
    }

    private func change(_ work: () throws -> Void) {
        do {
            try work()
            failure = nil
        } catch {
            failure = error.localizedDescription
        }
        refresh()
    }

    /// Reads launchd's records of the two agents for what they ask of the
    /// operator, unless a round is reading them or they are not both
    /// registered and allowed.
    private func readRecords() {
        guard roundTask == nil else {
            return
        }
        guard daemon == .enabled, applyJob == .enabled else {
            attention = .nothing
            untold = []
            return
        }
        guard reading == nil else {
            return
        }
        // Counted here, not when the task first runs: a round that
        // `start()` begins right after this has begun by then.
        let began = rounds
        reading = Task {
            let shown = await askLaunchd(asOf: began)
            reading = nil
            // Something overtook it: what there is to show now is read
            // afresh, unless a round is reading.
            if !shown {
                readRecords()
            }
        }
    }

    /// One reading of launchd's records of the two agents, asked for when
    /// `began` rounds had begun, and whether it was shown. A round that
    /// began since has the last word, and so has a stop or Login Items,
    /// after which the agents are no longer both registered and allowed.
    private func askLaunchd(asOf began: Int) async -> Bool {
        let asked: (attention: LaunchAttention, untold: [LaunchRoundFailure])
        do {
            let daemon = LaunchReading(try await launchctl.record(of: Self.label))
            let job = LaunchReading(try await launchctl.record(of: Self.applyLabel))
            asked = (LaunchAttention(daemon: daemon, job: job), LaunchRoundFailure.untold(daemon: daemon, job: job))
        } catch {
            asked = (.nothing, [.launchctl(error)])
        }
        guard rounds == began, daemon == .enabled, applyJob == .enabled else {
            return false
        }
        attention = asked.attention
        untold = asked.untold
        return true
    }
}

extension DaemonService: LaunchRoundHost {
    private static func label(of agent: LaunchAgent) -> String {
        switch agent {
        case .daemon: label
        case .applyJob: applyLabel
        }
    }

    func record(of agent: LaunchAgent) async throws(LaunchctlFailure) -> LaunchRecord? {
        try await launchctl.record(of: Self.label(of: agent))
    }

    func start(_ agent: LaunchAgent) async throws(LaunchctlFailure) {
        try await launchctl.kickstart(Self.label(of: agent))
    }

    /// The daemon, then the apply job, each if it is not registered: a
    /// registration that failed for one of them is made up for it alone.
    func registerAgents() throws {
        for service in [agent, applyAgent] where DaemonRegistration(service.status) == .notRegistered {
            try service.register()
        }
    }

    /// The daemon, then the apply job, each if it is registered: an app
    /// built before the apply job registered none, and a stop may come
    /// while a round has both unregistered.
    func unregisterAgents() throws {
        for service in [agent, applyAgent] where DaemonRegistration(service.status) != .notRegistered {
            try service.unregister()
        }
    }

    func pause(_ duration: Duration) async throws {
        try await Task.sleep(for: duration)
    }

    var now: ContinuousClock.Instant {
        ContinuousClock.now
    }

    func show(_ phase: LaunchRoundPhase) {
        if round != phase {
            round = phase
        }
    }
}
