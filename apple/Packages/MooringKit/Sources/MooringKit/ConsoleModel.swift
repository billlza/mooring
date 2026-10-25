// SPDX-License-Identifier: GPL-3.0-or-later

// The app's view of the console: the latest document from the stream, and
// the stream's own state. When the command ends (the daemon is not running,
// or stopped), the model says so with the command's own message and starts
// it again after `retryDelay`, visibly: a stale document stays on screen
// only under a state that says it is not live, and so does one that a
// newer, refused line has overtaken. A run started again keeps how the last
// one ended on screen until it shows a document, ends, or lasts
// `settleDelay`, so the screen does not flash back to connecting at every
// retry while the daemon is not running.

import Foundation
import Observation

/// Where the stream stands.
public enum StreamState: Hashable, Sendable {
    /// The command is starting, or waiting for the daemon's first status.
    case connecting
    /// The command was started again after it ended so, and has not yet
    /// shown a document, ended, or lasted `settleDelay`.
    case retrying(StreamEnd)
    /// Documents are arriving, and the latest was shown.
    case live
    /// The latest line was refused, so what is on screen is older than it;
    /// the next document shown makes the stream live again.
    case refusing(LineRefusal)
    /// The command ended; it is started again at `retryAt`.
    case ended(StreamEnd, retryAt: Date)
    /// The model was stopped: nothing is read.
    case stopped
    /// There is no `mooringctl` to run.
    case noCommand(String)
}

@MainActor
@Observable
public final class ConsoleModel {
    /// The latest document shown, if one has arrived.
    public private(set) var status: ConsoleStatus?
    /// The stream's state.
    public private(set) var state: StreamState = .connecting

    /// How long after the command ends it is started again.
    public let retryDelay: Duration
    /// How long a run started again lasts before the model says it is
    /// connecting: one that cannot reach the daemon ends sooner, so its
    /// retries keep the last end on screen, and one that lasts is waiting
    /// for the daemon's first status.
    public let settleDelay: Duration

    private let command: StatusCommand?
    /// The reading task. Only the main actor sets it; `deinit` cancels it,
    /// so a released model stops reading even while its stream is silent.
    @ObservationIgnored nonisolated(unsafe) private var runner: Task<Void, Never>?

    /// A model reading `command`; `nil` (no `mooringctl` in the bundle) is
    /// shown as such, with `missing` saying where it was looked for.
    public init(
        command: StatusCommand?, missing: String = "", retryDelay: Duration = .seconds(5),
        settleDelay: Duration = .seconds(2)
    ) {
        self.command = command
        self.retryDelay = retryDelay
        self.settleDelay = settleDelay
        if command == nil {
            state = .noCommand(missing)
        }
    }

    /// Starts reading; a second call does nothing. The task holds the model
    /// weakly: released, the model cancels it, which terminates the command.
    public func start() {
        guard runner == nil, let command else {
            return
        }
        state = .connecting
        runner = Task { [weak self, retryDelay] in
            // How the last run ended; none before the first.
            var ended: StreamEnd?
            while !Task.isCancelled {
                let settling = ended.flatMap { self?.retry(after: $0) }
                ended = nil
                for await event in command.events() {
                    guard let self else {
                        settling?.cancel()
                        return
                    }
                    self.apply(event)
                    if case .ended(let end) = event {
                        ended = end
                    }
                }
                settling?.cancel()
                guard ended != nil else {
                    // Cancelled before the command ended: no one reads on.
                    return
                }
                do {
                    try await Task.sleep(for: retryDelay)
                } catch {
                    return
                }
            }
        }
    }

    deinit {
        runner?.cancel()
    }

    /// Stops reading and terminates the command.
    public func stop() {
        runner?.cancel()
        runner = nil
        if command != nil {
            state = .stopped
        }
    }

    /// Applies one event.
    func apply(_ event: StreamEvent) {
        switch event {
        case .status(let status):
            self.status = status
            state = .live
        case .refused(let refusal):
            state = .refusing(refusal)
        case .ended(let end):
            state = .ended(end, retryAt: Date().addingTimeInterval(Self.seconds(retryDelay)))
        }
    }

    /// The command is started again after it ended with `end`: the screen
    /// keeps that end, retrying, and the returned timer settles it to
    /// connecting after `settleDelay`; the run cancels the timer when it
    /// ends.
    func retry(after end: StreamEnd) -> Task<Void, Never> {
        state = .retrying(end)
        return Task { [weak self, settleDelay] in
            do {
                try await Task.sleep(for: settleDelay)
            } catch {
                // The run ended first, or the model stopped.
                return
            }
            self?.settle(after: end)
        }
    }

    /// A run started again after `end` has lasted `settleDelay`: unless it
    /// has shown a document or ended meanwhile, it is waiting for the
    /// daemon's first status.
    func settle(after end: StreamEnd) {
        if state == .retrying(end) {
            state = .connecting
        }
    }

    /// `duration` in seconds, fractions included.
    static func seconds(_ duration: Duration) -> TimeInterval {
        let (seconds, attoseconds) = duration.components
        return TimeInterval(seconds) + TimeInterval(attoseconds) / 1e18
    }
}
