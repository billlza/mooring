// SPDX-License-Identifier: GPL-3.0-or-later

// The app's view of the console: the latest document from the stream, and
// the stream's own state. When the command ends (the daemon is not running,
// or stopped), the model says so with the command's own message and starts
// it again after `retryDelay`, visibly: a stale document stays on screen
// only under a state that says it is not live, and so does one that a
// newer, refused line has overtaken.

import Foundation
import Observation

/// Where the stream stands.
public enum StreamState: Hashable, Sendable {
    /// The command is starting, or waiting for the daemon's first status.
    case connecting
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

    private let command: StatusCommand?
    /// The reading task. Only the main actor sets it; `deinit` cancels it,
    /// so a released model stops reading even while its stream is silent.
    @ObservationIgnored nonisolated(unsafe) private var runner: Task<Void, Never>?

    /// A model reading `command`; `nil` (no `mooringctl` in the bundle) is
    /// shown as such, with `missing` saying where it was looked for.
    public init(command: StatusCommand?, missing: String = "", retryDelay: Duration = .seconds(5)) {
        self.command = command
        self.retryDelay = retryDelay
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
            while !Task.isCancelled {
                self?.state = .connecting
                for await event in command.events() {
                    guard let self else {
                        return
                    }
                    self.apply(event)
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

    /// `duration` in seconds, fractions included.
    static func seconds(_ duration: Duration) -> TimeInterval {
        let (seconds, attoseconds) = duration.components
        return TimeInterval(seconds) + TimeInterval(attoseconds) / 1e18
    }
}
