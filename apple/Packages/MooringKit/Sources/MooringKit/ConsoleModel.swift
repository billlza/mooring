// SPDX-License-Identifier: GPL-3.0-or-later

// The app's view of the console: the latest document from the stream, and
// the stream's own state. When the command ends (the daemon is not running,
// or stopped), the model says so with the command's own message and starts
// it again after `retryDelay`, visibly: a stale document stays on screen
// only under a banner that says it is not live.

import Foundation
import Observation

/// Where the stream stands.
public enum StreamState: Hashable, Sendable {
    /// The command is starting, or waiting for the daemon's first status.
    case connecting
    /// Documents are arriving.
    case live
    /// The command ended; it is started again at `retryAt`.
    case ended(StreamEnd, retryAt: Date)
    /// There is no `mooringctl` to run.
    case noCommand(String)
}

@MainActor
@Observable
public final class ConsoleModel {
    /// The latest document, if one has arrived.
    public private(set) var status: ConsoleStatus?
    /// When it arrived.
    public private(set) var receivedAt: Date?
    /// The stream's state.
    public private(set) var state: StreamState = .connecting
    /// The last line that was refused, if any.
    public private(set) var refusal: String?

    /// How long after the command ends it is started again.
    public let retryDelay: Duration

    private let command: StatusCommand?
    private var runner: Task<Void, Never>?

    /// A model reading `command`; `nil` (no `mooringctl` in the bundle) is
    /// shown as such, with `missing` saying where it was looked for.
    public init(command: StatusCommand?, missing: String = "", retryDelay: Duration = .seconds(5)) {
        self.command = command
        self.retryDelay = retryDelay
        if command == nil {
            state = .noCommand(missing)
        }
    }

    /// Starts reading; a second call does nothing.
    public func start() {
        guard runner == nil, let command else {
            return
        }
        runner = Task { [weak self] in
            while !Task.isCancelled {
                self?.state = .connecting
                for await event in command.events() {
                    self?.apply(event)
                }
                guard let delay = self?.retryDelay else {
                    return
                }
                do {
                    try await Task.sleep(for: delay)
                } catch {
                    return
                }
            }
        }
    }

    /// Stops reading and terminates the command.
    public func stop() {
        runner?.cancel()
        runner = nil
    }

    /// Applies one event.
    func apply(_ event: StreamEvent) {
        switch event {
        case .status(let status):
            self.status = status
            receivedAt = Date()
            state = .live
            refusal = nil
        case .refused(let message):
            refusal = message
        case .ended(let end):
            state = .ended(end, retryAt: Date().addingTimeInterval(TimeInterval(retryDelay.components.seconds)))
        }
    }
}
