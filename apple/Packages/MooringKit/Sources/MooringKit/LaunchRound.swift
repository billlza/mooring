// SPDX-License-Identifier: GPL-3.0-or-later

// Carrying the start of the app's two agents through after a new build
// (design §5.1), which the operator did by hand before: macOS refuses an
// agent whose record it made for another build, replaces the record at that
// agent's own second failed start, and lets the program run once the agents
// are registered again. launchd makes the daemon's second start itself, 60 s
// after the first; the apply job it starts once an hour, so the round
// starts it by hand, twice. Then it unregisters and registers both.
//
// The steps and their timing are the ones measured on 2026-11-13 with a
// throwaway app on macOS 27.2: the job started by hand 5 s and 25 s after
// the registration, both agents unregistered 20 s after macOS replaced the
// daemon's record and registered again 3 s later, the daemon running at
// once after that. Nothing here leaves what was measured: the daemon is
// never started by hand, the job's two starts are 20 s apart, the agents
// are registered again together, and no sooner after the replacement.
//
// A start by hand of the apply job whose record is good runs `mooringctl
// apply --pending`: by its own rule it does nothing outside 19:15 to
// 19:45 UTC, and inside that window it is the night's run. So the round
// starts an idle job by hand only once, in the registration in which it has
// just seen macOS refuse the daemon, which shows that the program changed
// since the records were made; any other start by hand is of a job it has
// seen refused, which cannot run.
//
// Two readings are not taken at their word. launchd gives a service its
// pid while `xpcproxy` has yet to become the service's program, and its
// log has a refused start run for 40 to 50 ms; what the record says in
// that time was not captured, so a daemon shown as running counts only
// once it has been shown so for `steady`. And a reading the round cannot
// act on, an agent launchd does not list or a state this build does not
// know, is taken again for `settle` before it ends the round: the moment
// after a registration was not read either.
//
// `LaunchRoundPlan` chooses each step from what launchd's records say and
// from the time, and does nothing itself; `LaunchRound` asks the host for
// the records and carries the steps out.

/// What the round is doing, for the screen.
public enum LaunchRoundPhase: Hashable, Sendable {
    /// Waiting for launchd's first start of the daemon.
    case starting
    /// macOS refused the start, as after a new build: waiting for it to
    /// replace its records, about a minute.
    case newBuild
    /// Unregistering and registering both agents.
    case registeringAgain
    /// Waiting for the daemon after registering again.
    case startingAgain
    /// The daemon runs, and the refused apply job is brought to its second
    /// failed start.
    case repairingJob
}

/// Why a round did not end with a running daemon and an apply job that
/// macOS lets start.
public enum LaunchRoundFailure: Hashable, Sendable {
    /// launchd does not list the agent.
    case notListed(LaunchAgent)
    /// launchd did not start the daemon in the time a start takes.
    case daemonNotStarted
    /// The daemon's program started and ended by itself; its exit.
    case daemonEnded(LaunchLastExit?)
    /// The apply job was started by hand, and launchd's record of it did
    /// not change.
    case startIgnored
    /// macOS refused the agent and did not replace its record in time.
    case notReplaced(LaunchAgent)
    /// macOS refuses the agent again after it was registered again.
    case stillRefused(LaunchAgent)
    /// launchd's record of the agent is in a state the round does not know;
    /// the record's lines.
    case unknownState(LaunchAgent, String)
    /// The round's whole time passed.
    case tookTooLong
    /// `launchctl` gave nothing to go on.
    case launchctl(LaunchctlFailure)
    /// The agents could not be unregistered or registered; the system's
    /// words.
    case registration(String)
}

extension LaunchRoundFailure {
    /// What keeps two readings from telling whether macOS lets the agents
    /// start, the daemon's first: an agent launchd does not list, or a
    /// record in a state this build does not know. Empty when both tell.
    public static func untold(daemon: LaunchReading, job: LaunchReading) -> [LaunchRoundFailure] {
        [(LaunchAgent.daemon, daemon), (.applyJob, job)].compactMap { agent, reading in
            switch reading {
            case .notListed: .notListed(agent)
            case .unknown(let seen): .unknownState(agent, seen)
            case .condition: nil
            }
        }
    }
}

/// How a round ended.
public enum LaunchRoundOutcome: Hashable, Sendable {
    /// launchd runs the daemon, and macOS refused nothing.
    case started
    /// macOS refused an agent, the agents were registered again, and
    /// launchd runs the daemon.
    case repaired
    /// It did not get there.
    case failed(LaunchRoundFailure)
    /// It was ended from outside, as by **Stop the Daemon**.
    case cancelled
}

/// What the round does next.
public enum LaunchRoundStep: Hashable, Sendable {
    /// Read the records again after the poll interval.
    case wait
    /// Ask launchd to start the agent now.
    case start(LaunchAgent)
    /// Unregister both agents, and register both again.
    case registerAgain
    /// The round is over.
    case finish(LaunchRoundOutcome)
}

/// Chooses the round's steps.
public struct LaunchRoundPlan: Sendable {
    public typealias Instant = ContinuousClock.Instant

    /// The round's times and bounds.
    public struct Timing: Hashable, Sendable {
        /// Between two readings of launchd's records.
        public var poll: Duration = .seconds(1)
        /// How long the daemon is shown as running before it counts as
        /// running: far longer than a refused start is.
        public var steady: Duration = .seconds(2)
        /// For launchd's first start of the daemon after a registration,
        /// for a start by hand to show in the record, and for a reading
        /// the round cannot act on to become one it can.
        public var settle: Duration = .seconds(10)
        /// From the round's beginning to the job's first start by hand:
        /// 5 s after the registration, as measured.
        public var firstJobStart: Duration = .seconds(5)
        /// Between two starts of the job by hand: 20 s, as measured.
        public var jobStartGap: Duration = .seconds(20)
        /// For launchd's own second start of the daemon, which comes 60 s
        /// after the first (the plist's `ThrottleInterval`).
        public var replacement: Duration = .seconds(90)
        /// From the sight of both records in order to unregistering the
        /// agents: 20 s after macOS replaced the daemon's, as measured.
        public var afterReplacement: Duration = .seconds(20)
        /// Between unregistering the agents and registering them: 3 s, as
        /// measured.
        public var registrationGap: Duration = .seconds(3)
        /// For the whole round: two rounds of a new build, and a wait.
        public var whole: Duration = .seconds(240)
        /// The most starts of the job by hand within one registration.
        public var jobStarts = 3
        /// The most times the agents are registered again in one round.
        public var registrations = 2

        public init() {}
    }

    public let timing: Timing
    /// What the round is doing, after the last step chosen.
    public private(set) var phase: LaunchRoundPhase = .starting

    private let began: Instant
    /// When the agents were last registered: the round's beginning, or its
    /// last registration.
    private var registered: Instant
    private var registrations = 0
    /// Since when the readings are ones the round cannot act on.
    private var unusableSince: Instant?
    /// Since when the daemon is shown as running.
    private var runningSince: Instant?
    /// When the daemon was first seen refused in this registration.
    private var daemonRefusedAt: Instant?
    /// When the job was first seen refused in this registration.
    private var jobRefusedAt: Instant?
    /// The job's starts by hand in this registration, and the last one.
    private var jobStarts = 0
    private var lastJobStart: Instant?
    /// Since when nothing more is needed before the agents are registered
    /// again.
    private var readySince: Instant?

    /// A round that begins at `began`, right after the agents were
    /// registered or later.
    public init(began: Instant, timing: Timing = Timing()) {
        self.timing = timing
        self.began = began
        self.registered = began
    }

    /// The next step, from what launchd says of the two agents at `now`.
    public mutating func next(daemon: LaunchReading, job: LaunchReading, now: Instant) -> LaunchRoundStep {
        if now - began > timing.whole {
            return .finish(.failed(.tookTooLong))
        }
        switch (daemon, job) {
        case (.notListed, _):
            return unusable(.notListed(.daemon), now: now)
        case (.unknown(let seen), _):
            return unusable(.unknownState(.daemon, seen), now: now)
        case (_, .notListed):
            return unusable(.notListed(.applyJob), now: now)
        case (_, .unknown(let seen)):
            return unusable(.unknownState(.applyJob, seen), now: now)
        case (.condition(let daemon), .condition(let job)):
            unusableSince = nil
            return step(daemon: daemon, job: job, now: now)
        }
    }

    /// The agents were registered again at `now`.
    public mutating func registeredAgain(at now: Instant) {
        registered = now
    }

    /// A reading the round cannot act on: taken again for `settle`, and
    /// the round's end if it stays.
    private mutating func unusable(_ failure: LaunchRoundFailure, now: Instant) -> LaunchRoundStep {
        let since = unusableSince ?? now
        unusableSince = since
        return now - since > timing.settle ? .finish(.failed(failure)) : .wait
    }

    private mutating func step(daemon: LaunchCondition, job: LaunchCondition, now: Instant) -> LaunchRoundStep {
        if daemon != .running {
            runningSince = nil
        }
        switch daemon {
        case .running:
            let since = runningSince ?? now
            runningSince = since
            return now - since < timing.steady ? .wait : whileTheDaemonRuns(job: job, now: now)
        case .idle:
            phase = registrations == 0 ? .starting : .startingAgain
            return now - registered > timing.settle ? .finish(.failed(.daemonNotStarted)) : .wait
        case .exited(let exit):
            return .finish(.failed(.daemonEnded(exit)))
        case .refusedOnce:
            phase = .newBuild
            let since = daemonRefusedAt ?? now
            daemonRefusedAt = since
            if let step = whileTheDaemonIsRefused(job: job, now: now) {
                return step
            }
            // launchd starts the daemon again by itself.
            return now - since > timing.replacement ? .finish(.failed(.notReplaced(.daemon))) : .wait
        case .recordReplaced:
            phase = .newBuild
            if let step = whileTheDaemonIsRefused(job: job, now: now) {
                return step
            }
            return registerAgain(for: .daemon, now: now)
        }
    }

    /// The daemon runs: the round is over unless macOS refuses the job.
    private mutating func whileTheDaemonRuns(job: LaunchCondition, now: Instant) -> LaunchRoundStep {
        switch job {
        case .running, .idle, .exited:
            return .finish(registrations > 0 ? .repaired : .started)
        case .refusedOnce:
            phase = .repairingJob
            return startTheRefusedJob(now: now)
        case .recordReplaced:
            phase = .repairingJob
            return registerAgain(for: .applyJob, now: now)
        }
    }

    /// macOS refuses the daemon, so the program has changed since the
    /// records were made: what the job needs before the agents are
    /// registered again, or `nil` when it needs nothing more.
    private mutating func whileTheDaemonIsRefused(job: LaunchCondition, now: Instant) -> LaunchRoundStep? {
        switch job {
        case .recordReplaced, .exited:
            // Replaced, or its program ran, so its record is good.
            return nil
        case .running:
            // It is not unregistered under a run.
            return .wait
        case .refusedOnce:
            return startTheRefusedJob(now: now)
        case .idle:
            // After a registration made by this round the job's record is
            // the replaced one, or was good before: it is not started by
            // hand again.
            guard registrations == 0 else {
                return nil
            }
            guard let started = lastJobStart else {
                return now - began < timing.firstJobStart ? .wait : startTheJob(now: now)
            }
            return now - started > timing.settle ? .finish(.failed(.startIgnored)) : .wait
        }
    }

    /// The job was refused once: its next start, by hand, has macOS replace
    /// its record.
    private mutating func startTheRefusedJob(now: Instant) -> LaunchRoundStep {
        let seen = jobRefusedAt ?? now
        jobRefusedAt = seen
        if now - (lastJobStart ?? seen) < timing.jobStartGap {
            return .wait
        }
        if jobStarts >= timing.jobStarts {
            return .finish(.failed(.notReplaced(.applyJob)))
        }
        return startTheJob(now: now)
    }

    private mutating func startTheJob(now: Instant) -> LaunchRoundStep {
        jobStarts += 1
        lastJobStart = now
        return .start(.applyJob)
    }

    /// Both agents are registered again, for `agent`'s replaced record,
    /// once the records have been in order for `afterReplacement`; what was
    /// seen of the registration that ends is forgotten.
    private mutating func registerAgain(for agent: LaunchAgent, now: Instant) -> LaunchRoundStep {
        guard registrations < timing.registrations else {
            return .finish(.failed(.stillRefused(agent)))
        }
        let since = readySince ?? now
        readySince = since
        if now - since < timing.afterReplacement {
            return .wait
        }
        registrations += 1
        readySince = nil
        runningSince = nil
        daemonRefusedAt = nil
        jobRefusedAt = nil
        jobStarts = 0
        lastJobStart = nil
        phase = .registeringAgain
        return .registerAgain
    }
}

/// What a round needs of the app: launchd's records, a start by hand, the
/// two registrations, the time, and the screen.
@MainActor
public protocol LaunchRoundHost: AnyObject {
    /// launchd's record of the agent, or `nil` when launchd does not list
    /// it.
    func record(of agent: LaunchAgent) async throws(LaunchctlFailure) -> LaunchRecord?
    /// Asks launchd to start the agent now.
    func start(_ agent: LaunchAgent) async throws(LaunchctlFailure)
    /// Unregisters both agents.
    func unregisterAgents() throws
    /// Registers both agents.
    func registerAgents() throws
    /// Waits; a cancelled task's wait throws `CancellationError`.
    func pause(_ duration: Duration) async throws
    /// The time.
    var now: ContinuousClock.Instant { get }
    /// The round is in `phase`: told after each reading of the records.
    func show(_ phase: LaunchRoundPhase)
}

/// Carries a round out.
@MainActor
public enum LaunchRound {
    /// Runs a round on `host` to its end. A cancelled task ends it where it
    /// is, and it acts on nothing it read before: between unregistering and
    /// registering, that leaves the agents unregistered, as **Stop the
    /// Daemon** means them to be.
    public static func run(
        on host: any LaunchRoundHost, timing: LaunchRoundPlan.Timing = LaunchRoundPlan.Timing()
    ) async -> LaunchRoundOutcome {
        var plan = LaunchRoundPlan(began: host.now, timing: timing)
        do {
            while true {
                let daemon = LaunchReading(try await host.record(of: .daemon))
                let job = LaunchReading(try await host.record(of: .applyJob))
                try Task.checkCancellation()
                let step = plan.next(daemon: daemon, job: job, now: host.now)
                host.show(plan.phase)
                switch step {
                case .finish(let outcome):
                    return outcome
                case .wait:
                    break
                case .start(let agent):
                    try await host.start(agent)
                case .registerAgain:
                    try host.unregisterAgents()
                    try await host.pause(timing.registrationGap)
                    try host.registerAgents()
                    plan.registeredAgain(at: host.now)
                }
                try await host.pause(timing.poll)
            }
        } catch let failure as LaunchctlFailure {
            // What `launchctl` says of agents that **Stop the Daemon** has
            // just unregistered is the stop's doing.
            return Task.isCancelled ? .cancelled : .failed(.launchctl(failure))
        } catch is CancellationError {
            return .cancelled
        } catch {
            return .failed(.registration(error.localizedDescription))
        }
    }
}

/// What launchd's records ask of the operator while no round runs.
public enum LaunchAttention: Hashable, Sendable {
    /// Nothing: macOS refuses neither agent, as far as the records tell.
    case nothing
    /// macOS refuses the daemon's start: a round carries it through.
    case daemonRefused
    /// The daemon is not refused, and macOS refuses the apply job: a round
    /// repairs it.
    case applyJobRefused

    /// What the two readings ask for.
    public init(daemon: LaunchReading, job: LaunchReading) {
        switch (daemon, job) {
        case (.condition(.refusedOnce), _), (.condition(.recordReplaced), _):
            self = .daemonRefused
        case (_, .condition(.refusedOnce)), (_, .condition(.recordReplaced)):
            self = .applyJobRefused
        default:
            self = .nothing
        }
    }
}
