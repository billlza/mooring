// SPDX-License-Identifier: GPL-3.0-or-later

// The one-shot history command and its model, against a stand-in
// `mooringctl`.

import Foundation
import Testing

@testable import MooringKit

@Suite(.timeLimit(.minutes(1))) struct HistoryCommandTests {
    private func fixture() throws -> Data {
        try Fixtures.data("contract/history-fixtures/radio.json")
    }

    @Test func theDocumentIsReadFromOneRunWithTheCliDefaultRange() async throws {
        let standIn = try StandIn(lines: [try fixture()])
        defer { try? standIn.remove() }
        let result = await HistoryCommand(executable: standIn.executable).run()
        #expect(try standIn.arguments == "router history --json ")
        #expect(result == .success(try RadioHistory.decode(line: try fixture())))
    }

    @Test func aFailedRunKeepsTheCommandsOwnWords() async throws {
        let standIn = try StandIn(
            stdout: Data(), stderr: Data("mooringctl: --since 2026-10-14 is after --until 2026-10-13\n".utf8), code: 1)
        defer { try? standIn.remove() }
        let result = await HistoryCommand(executable: standIn.executable).run()
        #expect(
            result
                == .failure(
                    .ended(
                        StreamEnd(
                            reason: .exited(1), message: "mooringctl: --since 2026-10-14 is after --until 2026-10-13"))))
    }

    @Test func outputPastTheBoundIsRefusedWhole() async throws {
        let standIn = try StandIn(stdout: Data(repeating: 0x78, count: HistoryCommand.outputLimit + 1))
        defer { try? standIn.remove() }
        let result = await HistoryCommand(executable: standIn.executable).run()
        #expect(result == .failure(.tooLong))
    }

    @Test func anotherVersionAndAnUnreadableDocumentAreRefused() async throws {
        let text = String(decoding: try fixture(), as: UTF8.self)
        let later = Data(text.replacingOccurrences(of: "\"version\": 1", with: "\"version\": 2").utf8)
        let standIn = try StandIn(lines: [later])
        defer { try? standIn.remove() }
        #expect(await HistoryCommand(executable: standIn.executable).run() == .failure(.unsupportedVersion(2)))
        let unreadable = try StandIn(stdout: Data("not json\n".utf8))
        defer { try? unreadable.remove() }
        guard case .failure(.unreadable) = await HistoryCommand(executable: unreadable.executable).run() else {
            Issue.record("not refused as unreadable")
            return
        }
    }

    @Test func aMissingExecutableIsNotStarted() async throws {
        let missing = URL(fileURLWithPath: "/nonexistent/mooringctl-\(UUID().uuidString)")
        guard case .failure(.ended(let end)) = await HistoryCommand(executable: missing).run(),
            case .notStarted = end.reason
        else {
            Issue.record("a missing executable was not reported as not started")
            return
        }
    }

    @MainActor
    @Test func theModelLoadsOnceAndKeepsAFailure() async throws {
        let standIn = try StandIn(lines: [try fixture()])
        defer { try? standIn.remove() }
        let model = HistoryModel(command: HistoryCommand(executable: standIn.executable))
        #expect(model.state == .idle)
        model.reload()
        #expect(model.state == .loading)
        let loaded = try await eventually {
            if case .loaded = model.state { return true }
            return false
        }
        #expect(loaded)
        guard case .loaded(let history, _) = model.state else {
            return
        }
        #expect(history == (try RadioHistory.decode(line: try fixture())))
        let failing = try StandIn(stdout: Data(), stderr: Data("mooringctl: no\n".utf8), code: 1)
        defer { try? failing.remove() }
        let failed = HistoryModel(command: HistoryCommand(executable: failing.executable))
        failed.reload()
        let seen = try await eventually {
            if case .failed(.ended(let end), _) = failed.state {
                return end == StreamEnd(reason: .exited(1), message: "mooringctl: no")
            }
            return false
        }
        #expect(seen)
        #expect(HistoryModel(command: nil).state == .noCommand)
    }
}

/// Waits up to 10 s for `condition`, asked on the main actor.
@MainActor
private func eventually(_ condition: @MainActor () -> Bool) async throws -> Bool {
    let deadline = Date().addingTimeInterval(10)
    while Date() < deadline {
        if condition() {
            return true
        }
        try await Task.sleep(for: .milliseconds(20))
    }
    return condition()
}
