// SPDX-License-Identifier: GPL-3.0-or-later

// The round that carries the agents' start through after a new build: the
// plan's steps from what launchd's records say, and the round run against
// a stand-in for launchd that behaves as macOS 27.2 did on 2026-11-13.

import Foundation
import Testing

@testable import MooringKit

@Suite struct LaunchRoundPlanTests {
    private let began = ContinuousClock.now

    private func at(_ seconds: Int) -> ContinuousClock.Instant {
        began + .seconds(seconds)
    }

    /// The plan's step for two records it knows, `second` seconds into the
    /// round.
    private func next(
        _ plan: inout LaunchRoundPlan, _ daemon: LaunchCondition, _ job: LaunchCondition, at second: Int
    ) -> LaunchRoundStep {
        plan.next(daemon: .condition(daemon), job: .condition(job), now: at(second))
    }

    @Test func aStartThatNothingRefusesEndsOnceTheDaemonIsSteady() {
        var plan = LaunchRoundPlan(began: began)
        #expect(plan.phase == .starting)
        #expect(next(&plan, .idle, .idle, at: 0) == .wait)
        #expect(next(&plan, .running, .idle, at: 1) == .wait)
        #expect(next(&plan, .running, .idle, at: 2) == .wait)
        #expect(next(&plan, .running, .idle, at: 3) == .finish(.started))
        #expect(plan.phase == .starting)
        for job in [LaunchCondition.idle, .exited(.code(0)), .exited(.code(1)), .running] {
            var plan = LaunchRoundPlan(began: began)
            #expect(next(&plan, .running, job, at: 1) == .wait, "\(job)")
            #expect(next(&plan, .running, job, at: 3) == .finish(.started), "\(job)")
        }
    }

    /// A start may be shown as running in the moment before macOS refuses
    /// it: the daemon counts as running only when it has been shown so for
    /// two seconds on end.
    @Test func aStartShownAsRunningForAMomentIsNotARunningDaemon() {
        var plan = LaunchRoundPlan(began: began)
        #expect(next(&plan, .running, .idle, at: 0) == .wait)
        #expect(next(&plan, .refusedOnce, .idle, at: 1) == .wait)
        #expect(plan.phase == .newBuild)
        #expect(next(&plan, .running, .idle, at: 2) == .wait)
        #expect(next(&plan, .running, .idle, at: 3) == .wait)
        #expect(next(&plan, .running, .idle, at: 4) == .finish(.started))
    }

    @Test func theDaemonIsGivenTenSecondsToStart() {
        var plan = LaunchRoundPlan(began: began)
        #expect(next(&plan, .idle, .idle, at: 10) == .wait)
        #expect(next(&plan, .idle, .idle, at: 11) == .finish(.failed(.daemonNotStarted)))
        // After the round's own registration, ten seconds from that.
        var again = LaunchRoundPlan(began: began)
        #expect(next(&again, .recordReplaced, .recordReplaced, at: 0) == .wait)
        #expect(next(&again, .recordReplaced, .recordReplaced, at: 20) == .registerAgain)
        again.registeredAgain(at: at(24))
        #expect(next(&again, .idle, .idle, at: 34) == .wait)
        #expect(again.phase == .startingAgain)
        #expect(next(&again, .idle, .idle, at: 35) == .finish(.failed(.daemonNotStarted)))
    }

    /// The whole of a new build's round, at the times measured: the job
    /// started by hand 5 s and 25 s after the registration, the daemon's
    /// record replaced at launchd's own second start, and both registered
    /// again 20 s after that.
    @Test func aNewBuildIsCarriedThrough() {
        var plan = LaunchRoundPlan(began: began)
        for second in 0..<5 {
            #expect(next(&plan, .refusedOnce, .idle, at: second) == .wait, "\(second)")
            #expect(plan.phase == .newBuild)
        }
        #expect(next(&plan, .refusedOnce, .idle, at: 5) == .start(.applyJob))
        for second in 6..<25 {
            #expect(next(&plan, .refusedOnce, .refusedOnce, at: second) == .wait, "\(second)")
        }
        #expect(next(&plan, .refusedOnce, .refusedOnce, at: 25) == .start(.applyJob))
        for second in 26..<60 {
            #expect(next(&plan, .refusedOnce, .recordReplaced, at: second) == .wait, "\(second)")
        }
        for second in 60..<80 {
            #expect(next(&plan, .recordReplaced, .recordReplaced, at: second) == .wait, "\(second)")
            #expect(plan.phase == .newBuild)
        }
        #expect(next(&plan, .recordReplaced, .recordReplaced, at: 80) == .registerAgain)
        #expect(plan.phase == .registeringAgain)
        plan.registeredAgain(at: at(84))
        #expect(next(&plan, .idle, .idle, at: 85) == .wait)
        #expect(plan.phase == .startingAgain)
        #expect(next(&plan, .running, .idle, at: 86) == .wait)
        #expect(next(&plan, .running, .idle, at: 87) == .wait)
        #expect(next(&plan, .running, .idle, at: 88) == .finish(.repaired))
    }

    /// The job's record may be good while the daemon's is not: its one
    /// start by hand then runs it, and it is left alone.
    @Test func aJobThatRunsIsStartedOnceAndLeftAlone() {
        var plan = LaunchRoundPlan(began: began)
        #expect(next(&plan, .refusedOnce, .idle, at: 5) == .start(.applyJob))
        #expect(next(&plan, .refusedOnce, .exited(.code(0)), at: 6) == .wait)
        #expect(next(&plan, .refusedOnce, .exited(.code(0)), at: 59) == .wait)
        #expect(next(&plan, .recordReplaced, .exited(.code(0)), at: 60) == .wait)
        #expect(next(&plan, .recordReplaced, .exited(.code(0)), at: 79) == .wait)
        #expect(next(&plan, .recordReplaced, .exited(.code(0)), at: 80) == .registerAgain)
    }

    @Test func theJobIsNotUnregisteredUnderARun() {
        var plan = LaunchRoundPlan(began: began)
        #expect(next(&plan, .recordReplaced, .idle, at: 5) == .start(.applyJob))
        #expect(next(&plan, .recordReplaced, .running, at: 6) == .wait)
        #expect(next(&plan, .recordReplaced, .running, at: 120) == .wait)
        // The 20 s run from when its run is seen to have ended.
        #expect(next(&plan, .recordReplaced, .exited(.code(1)), at: 121) == .wait)
        #expect(next(&plan, .recordReplaced, .exited(.code(1)), at: 140) == .wait)
        #expect(next(&plan, .recordReplaced, .exited(.code(1)), at: 141) == .registerAgain)
    }

    /// While the daemon runs nothing shows that the program changed, so an
    /// idle job is never started by hand.
    @Test func anIdleJobIsNotStartedWhileTheDaemonRuns() {
        var plan = LaunchRoundPlan(began: began)
        #expect(next(&plan, .running, .idle, at: 0) == .wait)
        for second in [5, 6, 30] {
            #expect(next(&plan, .running, .idle, at: second) == .finish(.started), "\(second)")
        }
    }

    /// A job found refused while the daemon runs, as after a build whose
    /// round the daemon alone went through: one start by hand, 20 s after
    /// it is seen, then both agents registered again, 20 s after that.
    @Test func aRefusedJobIsRepairedWhileTheDaemonRuns() {
        var plan = LaunchRoundPlan(began: began)
        #expect(next(&plan, .running, .refusedOnce, at: 0) == .wait)
        #expect(plan.phase == .starting)
        #expect(next(&plan, .running, .refusedOnce, at: 2) == .wait)
        #expect(plan.phase == .repairingJob)
        #expect(next(&plan, .running, .refusedOnce, at: 21) == .wait)
        #expect(next(&plan, .running, .refusedOnce, at: 22) == .start(.applyJob))
        #expect(next(&plan, .running, .recordReplaced, at: 23) == .wait)
        #expect(plan.phase == .repairingJob)
        #expect(next(&plan, .running, .recordReplaced, at: 42) == .wait)
        #expect(next(&plan, .running, .recordReplaced, at: 43) == .registerAgain)
        #expect(plan.phase == .registeringAgain)
        plan.registeredAgain(at: at(47))
        // The daemon that launchd started again is given its two seconds.
        #expect(next(&plan, .running, .idle, at: 48) == .wait)
        #expect(next(&plan, .running, .idle, at: 49) == .wait)
        #expect(next(&plan, .running, .idle, at: 50) == .finish(.repaired))
        // Found with its record replaced already, it needs no start.
        var later = LaunchRoundPlan(began: began)
        #expect(next(&later, .running, .recordReplaced, at: 0) == .wait)
        #expect(next(&later, .running, .recordReplaced, at: 2) == .wait)
        #expect(next(&later, .running, .recordReplaced, at: 21) == .wait)
        #expect(next(&later, .running, .recordReplaced, at: 22) == .registerAgain)
        #expect(later.phase == .registeringAgain)
    }

    /// After a registration of its own the round does not start an idle
    /// job by hand again, and it registers again at most twice.
    @Test func afterRegisteringAgainNothingIsStartedByHand() {
        var plan = LaunchRoundPlan(began: began)
        #expect(next(&plan, .refusedOnce, .recordReplaced, at: 0) == .wait)
        #expect(next(&plan, .recordReplaced, .recordReplaced, at: 60) == .wait)
        #expect(next(&plan, .recordReplaced, .recordReplaced, at: 80) == .registerAgain)
        plan.registeredAgain(at: at(84))
        // Refused again, the daemon has its 90 s from when that is seen.
        for second in 85..<176 {
            #expect(next(&plan, .refusedOnce, .idle, at: second) == .wait, "\(second)")
        }
        #expect(plan.phase == .newBuild)
        // Its record replaced, the 20 s are counted anew.
        #expect(next(&plan, .recordReplaced, .idle, at: 176) == .wait)
        #expect(next(&plan, .recordReplaced, .idle, at: 195) == .wait)
        #expect(next(&plan, .recordReplaced, .idle, at: 196) == .registerAgain)
        plan.registeredAgain(at: at(200))
        #expect(next(&plan, .recordReplaced, .idle, at: 230) == .finish(.failed(.stillRefused(.daemon))))
        // The same for the job, while the daemon runs.
        var job = LaunchRoundPlan(began: began)
        #expect(next(&job, .running, .recordReplaced, at: 0) == .wait)
        #expect(next(&job, .running, .recordReplaced, at: 2) == .wait)
        #expect(next(&job, .running, .recordReplaced, at: 22) == .registerAgain)
        #expect(next(&job, .running, .recordReplaced, at: 23) == .wait)
        #expect(next(&job, .running, .recordReplaced, at: 25) == .wait)
        #expect(next(&job, .running, .recordReplaced, at: 44) == .wait)
        #expect(next(&job, .running, .recordReplaced, at: 45) == .registerAgain)
        #expect(next(&job, .running, .recordReplaced, at: 46) == .wait)
        #expect(next(&job, .running, .recordReplaced, at: 48) == .finish(.failed(.stillRefused(.applyJob))))
    }

    /// The job's starts by hand are counted and timed within a
    /// registration: refused again after the round registered it again, it
    /// has its 20 s and its three starts anew.
    @Test func whatWasSeenOfARegistrationIsForgottenWithIt() {
        var plan = LaunchRoundPlan(began: began)
        #expect(next(&plan, .running, .refusedOnce, at: 0) == .wait)
        #expect(next(&plan, .running, .refusedOnce, at: 2) == .wait)
        #expect(next(&plan, .running, .refusedOnce, at: 22) == .start(.applyJob))
        #expect(next(&plan, .running, .recordReplaced, at: 23) == .wait)
        #expect(next(&plan, .running, .recordReplaced, at: 43) == .registerAgain)
        plan.registeredAgain(at: at(47))
        #expect(next(&plan, .running, .refusedOnce, at: 48) == .wait)
        #expect(next(&plan, .running, .refusedOnce, at: 50) == .wait)
        #expect(next(&plan, .running, .refusedOnce, at: 69) == .wait)
        #expect(next(&plan, .running, .refusedOnce, at: 70) == .start(.applyJob))
        #expect(next(&plan, .running, .refusedOnce, at: 90) == .start(.applyJob))
        #expect(next(&plan, .running, .refusedOnce, at: 110) == .start(.applyJob))
        #expect(next(&plan, .running, .refusedOnce, at: 130) == .finish(.failed(.notReplaced(.applyJob))))
    }

    @Test func aDaemonWhoseRecordIsNotReplacedInTimeFails() {
        var plan = LaunchRoundPlan(began: began)
        #expect(next(&plan, .refusedOnce, .recordReplaced, at: 10) == .wait)
        #expect(next(&plan, .refusedOnce, .recordReplaced, at: 100) == .wait)
        #expect(next(&plan, .refusedOnce, .recordReplaced, at: 101) == .finish(.failed(.notReplaced(.daemon))))
    }

    /// Three starts by hand, 20 s apart, and no more.
    @Test func aJobThatStaysRefusedFails() {
        var plan = LaunchRoundPlan(began: began)
        #expect(next(&plan, .refusedOnce, .idle, at: 5) == .start(.applyJob))
        #expect(next(&plan, .refusedOnce, .refusedOnce, at: 25) == .start(.applyJob))
        #expect(next(&plan, .refusedOnce, .refusedOnce, at: 44) == .wait)
        #expect(next(&plan, .refusedOnce, .refusedOnce, at: 45) == .start(.applyJob))
        #expect(next(&plan, .recordReplaced, .refusedOnce, at: 64) == .wait)
        #expect(next(&plan, .recordReplaced, .refusedOnce, at: 65) == .finish(.failed(.notReplaced(.applyJob))))
    }

    @Test func aStartByHandThatChangesNothingFails() {
        var plan = LaunchRoundPlan(began: began)
        #expect(next(&plan, .refusedOnce, .idle, at: 5) == .start(.applyJob))
        #expect(next(&plan, .refusedOnce, .idle, at: 15) == .wait)
        #expect(next(&plan, .refusedOnce, .idle, at: 16) == .finish(.failed(.startIgnored)))
    }

    /// launchd may not list an agent in the moment after it is registered:
    /// the reading is taken again for ten seconds.
    @Test func anAgentLaunchdDoesNotListIsReadAgainAndThenFails() {
        var plan = LaunchRoundPlan(began: began)
        #expect(plan.next(daemon: .notListed, job: .condition(.idle), now: at(0)) == .wait)
        #expect(plan.next(daemon: .notListed, job: .condition(.idle), now: at(10)) == .wait)
        #expect(
            plan.next(daemon: .notListed, job: .condition(.idle), now: at(11))
                == .finish(.failed(.notListed(.daemon))))
        // A reading the round can act on begins the ten seconds anew.
        var again = LaunchRoundPlan(began: began)
        #expect(again.next(daemon: .notListed, job: .notListed, now: at(0)) == .wait)
        #expect(next(&again, .idle, .idle, at: 5) == .wait)
        #expect(again.next(daemon: .notListed, job: .notListed, now: at(12)) == .wait)
        #expect(again.next(daemon: .notListed, job: .notListed, now: at(22)) == .wait)
        #expect(
            again.next(daemon: .notListed, job: .notListed, now: at(23))
                == .finish(.failed(.notListed(.daemon))))
        var job = LaunchRoundPlan(began: began)
        #expect(job.next(daemon: .condition(.running), job: .notListed, now: at(0)) == .wait)
        #expect(
            job.next(daemon: .condition(.running), job: .notListed, now: at(11))
                == .finish(.failed(.notListed(.applyJob))))
    }

    @Test func aStateTheRoundDoesNotKnowIsReadAgainAndThenFailsWithTheRecordsLines() {
        var plan = LaunchRoundPlan(began: began)
        #expect(plan.next(daemon: .unknown("state = waiting"), job: .condition(.idle), now: at(0)) == .wait)
        #expect(plan.next(daemon: .unknown("state = waiting"), job: .notListed, now: at(10)) == .wait)
        #expect(
            plan.next(daemon: .unknown("state = waiting"), job: .notListed, now: at(11))
                == .finish(.failed(.unknownState(.daemon, "state = waiting"))))
        for daemon in [LaunchCondition.running, .idle, .exited(nil), .refusedOnce, .recordReplaced] {
            var plan = LaunchRoundPlan(began: began)
            #expect(plan.next(daemon: .condition(daemon), job: .unknown("runs = 4"), now: at(0)) == .wait, "\(daemon)")
            #expect(
                plan.next(daemon: .condition(daemon), job: .unknown("runs = 4"), now: at(11))
                    == .finish(.failed(.unknownState(.applyJob, "runs = 4"))), "\(daemon)")
        }
    }

    /// Outside a round the app says what the readings do not tell: the
    /// same that ends a round, the daemon's first.
    @Test func whatReadingsDoNotTellIsWhatEndsARound() {
        let known: [LaunchReading] = [.condition(.running), .condition(.idle), .condition(.refusedOnce)]
        for daemon in known {
            for job in known {
                #expect(LaunchRoundFailure.untold(daemon: daemon, job: job).isEmpty, "\(daemon) \(job)")
            }
        }
        let untold: [(LaunchReading, LaunchReading, [LaunchRoundFailure])] = [
            (.notListed, .condition(.idle), [.notListed(.daemon)]),
            (.condition(.running), .notListed, [.notListed(.applyJob)]),
            (.unknown("a"), .condition(.idle), [.unknownState(.daemon, "a")]),
            (.condition(.running), .unknown("b"), [.unknownState(.applyJob, "b")]),
            (.notListed, .unknown("b"), [.notListed(.daemon), .unknownState(.applyJob, "b")]),
            (.unknown("a"), .notListed, [.unknownState(.daemon, "a"), .notListed(.applyJob)]),
        ]
        for (daemon, job, expected) in untold {
            #expect(LaunchRoundFailure.untold(daemon: daemon, job: job) == expected, "\(daemon) \(job)")
            var plan = LaunchRoundPlan(began: began)
            #expect(plan.next(daemon: daemon, job: job, now: at(0)) == .wait, "\(daemon) \(job)")
            #expect(
                plan.next(daemon: daemon, job: job, now: at(11)) == .finish(.failed(expected[0])),
                "\(daemon) \(job)")
        }
    }

    /// A daemon whose program ends by itself is no matter of the
    /// registration: launchd starts it again, and its log says why.
    @Test func aDaemonThatEndsByItselfEndsTheRound() {
        var plan = LaunchRoundPlan(began: began)
        #expect(next(&plan, .exited(.code(1)), .idle, at: 3) == .finish(.failed(.daemonEnded(.code(1)))))
    }

    @Test func theWholeRoundIsBounded() {
        var plan = LaunchRoundPlan(began: began)
        #expect(next(&plan, .recordReplaced, .running, at: 240) == .wait)
        #expect(next(&plan, .recordReplaced, .running, at: 241) == .finish(.failed(.tookTooLong)))
        #expect(next(&plan, .running, .idle, at: 241) == .finish(.failed(.tookTooLong)))
        #expect(plan.next(daemon: .notListed, job: .notListed, now: at(241)) == .finish(.failed(.tookTooLong)))
    }

    @Test func theTimesAreTheMeasuredOnes() {
        let timing = LaunchRoundPlan.Timing()
        #expect(timing.poll == .seconds(1))
        #expect(timing.steady == .seconds(2))
        #expect(timing.settle == .seconds(10))
        #expect(timing.firstJobStart == .seconds(5))
        #expect(timing.jobStartGap == .seconds(20))
        #expect(timing.replacement == .seconds(90))
        #expect(timing.afterReplacement == .seconds(20))
        #expect(timing.registrationGap == .seconds(3))
        #expect(timing.whole == .seconds(240))
        #expect(timing.jobStarts == 3)
        #expect(timing.registrations == 2)
    }
}

/// launchd and macOS's records, as the round's host: an agent whose record
/// was made for another build is refused, its second failed start has the
/// record replaced, and a registration after that finds a good one. launchd
/// starts the daemon when it is registered and, refused, again every 60 s;
/// it starts the job only when asked. Time passes only in `pause`.
@MainActor
private final class StandInLaunchd: LaunchRoundHost {
    struct Refused: Error {}

    static let notFound = LaunchctlFailure.ended(
        arguments: ["kickstart", "gui/501/com.example.job"],
        StreamEnd(reason: .exited(113), message: "Could not find service"))

    var stale: Set<LaunchAgent>
    private var replaced: Set<LaunchAgent> = []
    private var jobFailedStarts: Int
    private var jobRuns = 0
    private var registered = true
    private var registeredAt: ContinuousClock.Instant
    private let began: ContinuousClock.Instant
    private var clock: ContinuousClock.Instant

    private(set) var starts: [LaunchAgent] = []
    private(set) var unregistrations = 0
    private(set) var registrations = 0
    private(set) var phases: [LaunchRoundPhase] = []

    /// A refused start of the daemon is shown as running at its instant.
    var showsARefusedStartAsRunning = false
    /// For this long after a registration launchd lists neither agent.
    var listsAfter: Duration = .zero
    var recordFailure: LaunchctlFailure?
    var startFailure: LaunchctlFailure?
    var unregisterFails = false
    var registerFails = false
    /// The round's task is cancelled in the first pause this long after
    /// the beginning.
    var cancelAfter: Duration?
    /// The round's task is cancelled under the first reading this long
    /// after the beginning, which is answered all the same.
    var cancelUnderReadingAfter: Duration?
    /// The round's task is cancelled under a start by hand, and launchd no
    /// longer finds the agent.
    var cancelUnderStart = false

    /// `registeredFor` is how long ago the agents were registered;
    /// `jobFailedStarts` the job's refused starts since.
    init(stale: Set<LaunchAgent>, registeredFor: Duration = .zero, jobFailedStarts: Int = 0) {
        self.stale = stale
        self.jobFailedStarts = jobFailedStarts
        began = ContinuousClock.now
        clock = began
        registeredAt = began - registeredFor
        if jobFailedStarts >= 2 {
            replaced.insert(.applyJob)
        }
    }

    var elapsed: Duration { clock - began }
    var isRegistered: Bool { registered }
    var now: ContinuousClock.Instant { clock }

    func unregister() {
        registered = false
    }

    private func cancelTheRound() {
        withUnsafeCurrentTask { $0?.cancel() }
    }

    private func refused(runs: Int, state: String, properties: [String]) -> LaunchRecord {
        LaunchRecord(
            state: state, runs: runs, lastExit: runs >= 2 ? .code(78) : nil, jobState: "spawn failed",
            properties: properties + ["needs LWCR update", "has LWCR"])
    }

    func record(of agent: LaunchAgent) async throws(LaunchctlFailure) -> LaunchRecord? {
        if let cancelUnderReadingAfter, elapsed >= cancelUnderReadingAfter {
            cancelTheRound()
        }
        if let recordFailure {
            throw recordFailure
        }
        let since = clock - registeredAt
        guard registered, since >= listsAfter else {
            return nil
        }
        switch agent {
        case .daemon:
            if stale.contains(.daemon) {
                let failed = 1 + Int(since / .seconds(60))
                if failed >= 2 {
                    replaced.insert(.daemon)
                }
                if showsARefusedStartAsRunning, since == .seconds(60 * (failed - 1)) {
                    return LaunchRecord(
                        state: "running", runs: failed, lastExit: nil, jobState: nil,
                        properties: ["keepalive", "runatload", "has LWCR"])
                }
                return refused(runs: failed, state: "spawn scheduled", properties: ["keepalive", "runatload"])
            }
            // launchd's start takes a moment.
            return since < .seconds(2)
                ? LaunchRecord(state: "spawn scheduled", runs: 0, lastExit: .never, jobState: nil, properties: [])
                : LaunchRecord(
                    state: "running", runs: 1, lastExit: .never, jobState: "running", properties: ["has LWCR"])
        case .applyJob:
            if jobFailedStarts > 0 {
                return refused(runs: jobFailedStarts, state: "not running", properties: [])
            }
            return jobRuns == 0
                ? LaunchRecord(
                    state: "not running", runs: 0, lastExit: .never, jobState: "uninitialized",
                    properties: ["has LWCR"])
                : LaunchRecord(
                    state: "not running", runs: jobRuns, lastExit: .code(0), jobState: "exited",
                    properties: ["has LWCR"])
        }
    }

    func start(_ agent: LaunchAgent) async throws(LaunchctlFailure) {
        if cancelUnderStart {
            cancelTheRound()
            throw Self.notFound
        }
        if let startFailure {
            throw startFailure
        }
        starts.append(agent)
        guard agent == .applyJob else {
            return
        }
        if stale.contains(.applyJob) {
            jobFailedStarts += 1
            if jobFailedStarts >= 2 {
                replaced.insert(.applyJob)
            }
        } else {
            jobRuns += 1
        }
    }

    func unregisterAgents() throws {
        if unregisterFails {
            throw Refused()
        }
        unregistrations += 1
        registered = false
    }

    func registerAgents() throws {
        if registerFails {
            throw Refused()
        }
        registrations += 1
        registered = true
        registeredAt = clock
        stale.subtract(replaced)
        replaced = []
        jobFailedStarts = 0
        jobRuns = 0
    }

    func pause(_ duration: Duration) async throws {
        if let cancelAfter, elapsed >= cancelAfter {
            cancelTheRound()
        }
        try Task.checkCancellation()
        clock += duration
    }

    func show(_ phase: LaunchRoundPhase) {
        if phases.last != phase {
            phases.append(phase)
        }
    }
}

@MainActor
@Suite(.timeLimit(.minutes(1))) struct LaunchRoundTests {
    @Test func aNewBuildsStartIsCarriedThrough() async {
        let launchd = StandInLaunchd(stale: [.daemon, .applyJob])
        #expect(await LaunchRound.run(on: launchd) == .repaired)
        #expect(launchd.starts == [.applyJob, .applyJob])
        #expect(launchd.unregistrations == 1)
        #expect(launchd.registrations == 1)
        #expect(launchd.stale.isEmpty)
        #expect(launchd.isRegistered)
        // The first reading already shows the daemon refused.
        #expect(launchd.phases == [.newBuild, .registeringAgain, .startingAgain])
        // The daemon's record is replaced 60 s after the registration; then
        // 20 s, 3 s between unregistering and registering, 2 s for the
        // start, and 2 s of the daemon shown as running.
        #expect(launchd.elapsed == .seconds(87))
    }

    @Test func aBuildMacOSKnowsStartsWithNothingMore() async {
        let launchd = StandInLaunchd(stale: [])
        #expect(await LaunchRound.run(on: launchd) == .started)
        #expect(launchd.starts.isEmpty)
        #expect(launchd.unregistrations == 0)
        #expect(launchd.registrations == 0)
        #expect(launchd.phases == [.starting])
        #expect(launchd.elapsed == .seconds(4))
        // With other times than its own, the round keeps to them: read
        // every 3 s, the daemon is shown as running at 3 s and has been for
        // 5 s at 9 s.
        var timing = LaunchRoundPlan.Timing()
        timing.poll = .seconds(3)
        timing.steady = .seconds(5)
        let slower = StandInLaunchd(stale: [])
        #expect(await LaunchRound.run(on: slower, timing: timing) == .started)
        #expect(slower.elapsed == .seconds(9))
    }

    /// Both of the daemon's refused starts are shown as running when the
    /// round reads them: neither ends the round.
    @Test func aRefusedStartShownAsRunningDoesNotEndTheRound() async {
        let launchd = StandInLaunchd(stale: [.daemon, .applyJob])
        launchd.showsARefusedStartAsRunning = true
        #expect(await LaunchRound.run(on: launchd) == .repaired)
        #expect(launchd.starts == [.applyJob, .applyJob])
        #expect(launchd.registrations == 1)
        #expect(launchd.stale.isEmpty)
        #expect(launchd.elapsed == .seconds(88))
    }

    /// launchd lists the agents two seconds after they are registered.
    @Test func agentsNotListedForAMomentAreWaitedFor() async {
        let launchd = StandInLaunchd(stale: [.daemon, .applyJob])
        launchd.listsAfter = .seconds(2)
        #expect(await LaunchRound.run(on: launchd) == .repaired)
        #expect(launchd.registrations == 1)
        #expect(launchd.stale.isEmpty)
        // And agents that are not registered are not waited for longer
        // than ten seconds.
        let none = StandInLaunchd(stale: [])
        none.unregister()
        #expect(await LaunchRound.run(on: none) == .failed(.notListed(.daemon)))
        #expect(none.elapsed == .seconds(11))
        #expect(none.registrations == 0)
    }

    /// The daemon's record is another build's and the job's is good: the
    /// job's one start by hand runs it, and the daemon is carried through.
    @Test func aGoodJobIsStartedOnceWithARefusedDaemon() async {
        let launchd = StandInLaunchd(stale: [.daemon])
        #expect(await LaunchRound.run(on: launchd) == .repaired)
        #expect(launchd.starts == [.applyJob])
        #expect(launchd.registrations == 1)
        #expect(launchd.stale.isEmpty)
    }

    /// The job found refused an hour after a build whose round only the
    /// daemon went through.
    @Test func aRefusedJobIsRepairedUnderARunningDaemon() async {
        let launchd = StandInLaunchd(stale: [.applyJob], registeredFor: .seconds(3600), jobFailedStarts: 1)
        #expect(await LaunchRound.run(on: launchd) == .repaired)
        #expect(launchd.starts == [.applyJob])
        #expect(launchd.unregistrations == 1)
        #expect(launchd.registrations == 1)
        #expect(launchd.stale.isEmpty)
        #expect(launchd.phases == [.starting, .repairingJob, .registeringAgain, .startingAgain])
        // And one found after its second refused start needs no start.
        let replaced = StandInLaunchd(stale: [.applyJob], registeredFor: .seconds(7200), jobFailedStarts: 2)
        #expect(await LaunchRound.run(on: replaced) == .repaired)
        #expect(replaced.starts.isEmpty)
        #expect(replaced.stale.isEmpty)
    }

    /// A job whose record is another build's is not touched while the
    /// daemon runs and launchd has not started it: nothing shows it.
    @Test func aStaleJobThatHasNotBeenStartedIsNotSeen() async {
        let launchd = StandInLaunchd(stale: [.applyJob], registeredFor: .seconds(600))
        #expect(await LaunchRound.run(on: launchd) == .started)
        #expect(launchd.starts.isEmpty)
        #expect(launchd.stale == [.applyJob])
    }

    @Test func whatLaunchctlCannotTellEndsTheRound() async {
        let failure = LaunchctlFailure.unreadable(service: "gui/501/x", .missing("state"))
        let unread = StandInLaunchd(stale: [.daemon, .applyJob])
        unread.recordFailure = failure
        #expect(await LaunchRound.run(on: unread) == .failed(.launchctl(failure)))
        #expect(unread.starts.isEmpty)
        let unstarted = StandInLaunchd(stale: [.daemon, .applyJob])
        unstarted.startFailure = StandInLaunchd.notFound
        #expect(await LaunchRound.run(on: unstarted) == .failed(.launchctl(StandInLaunchd.notFound)))
        #expect(unstarted.unregistrations == 0)
        #expect(unstarted.elapsed == .seconds(5))
    }

    /// A registration that fails after the agents were unregistered leaves
    /// them unregistered, and the round says why.
    @Test func aRegistrationThatFailsEndsTheRound() async {
        let description = StandInLaunchd.Refused().localizedDescription
        let launchd = StandInLaunchd(stale: [.daemon, .applyJob])
        launchd.registerFails = true
        #expect(await LaunchRound.run(on: launchd) == .failed(.registration(description)))
        #expect(launchd.unregistrations == 1)
        #expect(!launchd.isRegistered)
        let kept = StandInLaunchd(stale: [.daemon, .applyJob])
        kept.unregisterFails = true
        #expect(await LaunchRound.run(on: kept) == .failed(.registration(description)))
        #expect(kept.isRegistered)
        #expect(kept.registrations == 0)
    }

    /// **Stop the Daemon** ends a round where it is.
    @Test func aCancelledRoundStopsWhereItIs() async {
        let launchd = StandInLaunchd(stale: [.daemon, .applyJob])
        launchd.cancelAfter = .seconds(10)
        let outcome = await Task { await LaunchRound.run(on: launchd) }.value
        #expect(outcome == .cancelled)
        #expect(launchd.starts == [.applyJob])
        #expect(launchd.unregistrations == 0)
        #expect(launchd.elapsed == .seconds(10))
        // Between unregistering and registering, the agents stay
        // unregistered.
        let between = StandInLaunchd(stale: [.daemon, .applyJob])
        between.cancelAfter = .seconds(80)
        let ended = await Task { await LaunchRound.run(on: between) }.value
        #expect(ended == .cancelled)
        #expect(between.unregistrations == 1)
        #expect(between.registrations == 0)
        #expect(!between.isRegistered)
    }

    /// A round ended while `launchctl` ran acts on nothing it has read: at
    /// 5 s the records ask for the job's start by hand, and at 80 s for a
    /// new registration.
    @Test func aRoundCancelledUnderAReadingDoesNothingMore() async {
        let early = StandInLaunchd(stale: [.daemon, .applyJob])
        early.cancelUnderReadingAfter = .seconds(5)
        let outcome = await Task { await LaunchRound.run(on: early) }.value
        #expect(outcome == .cancelled)
        #expect(early.starts.isEmpty)
        #expect(early.elapsed == .seconds(5))
        let late = StandInLaunchd(stale: [.daemon, .applyJob])
        late.cancelUnderReadingAfter = .seconds(80)
        let ended = await Task { await LaunchRound.run(on: late) }.value
        #expect(ended == .cancelled)
        #expect(late.unregistrations == 0)
        #expect(late.isRegistered)
    }

    /// The stop unregistered the job while the round asked launchd to
    /// start it: what `launchctl` says of that is not the round's failure.
    @Test func aStartThatFailsUnderACancelledRoundIsTheStopsDoing() async {
        let launchd = StandInLaunchd(stale: [.daemon, .applyJob])
        launchd.cancelUnderStart = true
        let outcome = await Task { await LaunchRound.run(on: launchd) }.value
        #expect(outcome == .cancelled)
        #expect(launchd.starts.isEmpty)
    }
}
