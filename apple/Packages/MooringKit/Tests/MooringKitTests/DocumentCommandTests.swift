// SPDX-License-Identifier: GPL-3.0-or-later

// The one-shot document commands and their model, against a stand-in
// `mooringctl`: the history's and the event journals'.

import Foundation
import Testing

@testable import MooringKit

@Suite(.timeLimit(.minutes(1))) struct DocumentCommandTests {
    private func historyFixture() throws -> Data {
        try Fixtures.data("contract/history-fixtures/radio.json")
    }

    private func eventsFixture() throws -> Data {
        try Fixtures.data("contract/events-fixtures/events.json")
    }

    @Test func eachDocumentIsReadFromOneRunWithTheCliDefaultRange() async throws {
        let history = try StandIn(lines: [try historyFixture()])
        defer { try? history.remove() }
        let read = await DocumentCommand<RadioHistory>(executable: history.executable).run()
        #expect(try history.arguments == "router history --json ")
        #expect(read == .success(try RadioHistory.decode(line: try historyFixture())))
        let journals = try StandIn(lines: [try eventsFixture()])
        defer { try? journals.remove() }
        let events = await DocumentCommand<EventsDocument>(executable: journals.executable).run()
        #expect(try journals.arguments == "events --json ")
        #expect(events == .success(try EventsDocument.decode(line: try eventsFixture())))
    }

    @Test func aFailedRunKeepsTheCommandsOwnWords() async throws {
        let standIn = try StandIn(
            stdout: Data(), stderr: Data("mooringctl: --since 2026-10-14 is after --until 2026-10-13\n".utf8), code: 1)
        defer { try? standIn.remove() }
        let result = await DocumentCommand<RadioHistory>(executable: standIn.executable).run()
        #expect(
            result
                == .failure(
                    .ended(
                        StreamEnd(
                            reason: .exited(1),
                            message: "mooringctl: --since 2026-10-14 is after --until 2026-10-13"))))
    }

    /// Each document's bound: 4 MiB, past which the output is refused
    /// whole, the failure naming the bound.
    @Test func outputPastTheBoundIsRefusedWhole() async throws {
        #expect(RadioHistory.outputLimit == 4_194_304)
        #expect(EventsDocument.outputLimit == 4_194_304)
        let standIn = try StandIn(stdout: Data(repeating: 0x78, count: EventsDocument.outputLimit + 1))
        defer { try? standIn.remove() }
        let result = await DocumentCommand<EventsDocument>(executable: standIn.executable).run()
        #expect(result == .failure(.tooLong(limit: 4_194_304)))
    }

    @Test func anotherVersionAndAnUnreadableDocumentAreRefused() async throws {
        let text = String(decoding: try eventsFixture(), as: UTF8.self)
        let later = Data(text.replacingOccurrences(of: "\"version\": 1", with: "\"version\": 2").utf8)
        let standIn = try StandIn(lines: [later])
        defer { try? standIn.remove() }
        #expect(
            await DocumentCommand<EventsDocument>(executable: standIn.executable).run()
                == .failure(.unsupportedVersion(found: 2, reads: 1)))
        let unreadable = try StandIn(stdout: Data("not json\n".utf8))
        defer { try? unreadable.remove() }
        guard case .failure(.unreadable) = await DocumentCommand<RadioHistory>(executable: unreadable.executable).run()
        else {
            Issue.record("not refused as unreadable")
            return
        }
    }

    @Test func aMissingExecutableIsNotStarted() async throws {
        let missing = URL(fileURLWithPath: "/nonexistent/mooringctl-\(UUID().uuidString)")
        guard case .failure(.ended(let end)) = await DocumentCommand<EventsDocument>(executable: missing).run(),
            case .notStarted = end.reason
        else {
            Issue.record("a missing executable was not reported as not started")
            return
        }
    }

    @MainActor
    @Test func theModelLoadsOnceAndKeepsAFailure() async throws {
        let standIn = try StandIn(lines: [try eventsFixture()])
        defer { try? standIn.remove() }
        let model = DocumentModel(command: DocumentCommand<EventsDocument>(executable: standIn.executable))
        #expect(model.state == .idle)
        model.reload()
        #expect(model.state == .loading)
        let loaded = try await eventually {
            if case .loaded = model.state { return true }
            return false
        }
        #expect(loaded)
        guard case .loaded(let document, _) = model.state else {
            return
        }
        #expect(document == (try EventsDocument.decode(line: try eventsFixture())))
        let failing = try StandIn(stdout: Data(), stderr: Data("mooringctl: no\n".utf8), code: 1)
        defer { try? failing.remove() }
        let failed = DocumentModel(command: DocumentCommand<RadioHistory>(executable: failing.executable))
        failed.reload()
        let seen = try await eventually {
            if case .failed(.ended(let end), _) = failed.state {
                return end == StreamEnd(reason: .exited(1), message: "mooringctl: no")
            }
            return false
        }
        #expect(seen)
        #expect(DocumentModel<RadioHistory>(command: nil).state == .noCommand)
    }

    /// A Reload while a run is under way starts no second run, and a model
    /// with no command to run stays so.
    @MainActor
    @Test func aReloadWhileOneRunsStartsNoOther() async throws {
        let standIn = try StandIn(lines: [try historyFixture()])
        defer { try? standIn.remove() }
        let model = DocumentModel(command: DocumentCommand<RadioHistory>(executable: standIn.executable))
        model.reload()
        model.reload()
        let loaded = try await eventually {
            if case .loaded = model.state { return true }
            return false
        }
        #expect(loaded)
        #expect(standIn.runs.count == 1)
        let none = DocumentModel<EventsDocument>(command: nil)
        none.reload()
        #expect(none.state == .noCommand)
    }
}
