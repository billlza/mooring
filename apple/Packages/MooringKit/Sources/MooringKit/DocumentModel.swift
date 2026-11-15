// SPDX-License-Identifier: GPL-3.0-or-later

// A screen's one-shot document (the Router screen's history, the Events
// screen's journals): the last run of its command and where it stands.
// Run when the screen first asks and on Reload; a run that failed keeps
// the command's own words on screen until the next.

import Foundation
import Observation

/// Where a document stands.
public enum DocumentState<Document: CommandDocument>: Hashable, Sendable {
    /// Not asked for yet.
    case idle
    /// The command runs.
    case loading
    /// The document, and when the command returned it.
    case loaded(Document, at: Date)
    /// Why there is no document, and when the command said so.
    case failed(DocumentFailure, at: Date)
    /// There is no `mooringctl` to run.
    case noCommand
}

@MainActor
@Observable
public final class DocumentModel<Document: CommandDocument> {
    /// Where the document stands.
    public private(set) var state: DocumentState<Document>

    private let command: DocumentCommand<Document>?
    /// The run in progress. Only the main actor sets it; `deinit` cancels
    /// it, so a released model stops waiting on its command.
    @ObservationIgnored nonisolated(unsafe) private var runner: Task<Void, Never>?

    /// A model running `command`; `nil` (no `mooringctl` in the bundle) is
    /// shown as such.
    public init(command: DocumentCommand<Document>?) {
        self.command = command
        state = command == nil ? .noCommand : .idle
    }

    /// Runs the command once; a call while one runs does nothing.
    public func reload() {
        guard let command, runner == nil else {
            return
        }
        state = .loading
        runner = Task { [weak self] in
            let result = await command.run()
            self?.apply(result)
        }
    }

    deinit {
        runner?.cancel()
    }

    /// Applies a run's result.
    func apply(_ result: Result<Document, DocumentFailure>) {
        runner = nil
        switch result {
        case .success(let document):
            state = .loaded(document, at: Date())
        case .failure(let failure):
            state = .failed(failure, at: Date())
        }
    }
}
