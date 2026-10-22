// SPDX-License-Identifier: GPL-3.0-or-later

// The command runner and the model, against a stand-in `mooringctl`: a
// shell script that prints fixture lines and an error, and exits.

import Foundation
import Testing

@testable import MooringKit

/// A directory holding a stand-in `mooringctl` and its inputs.
private struct StandIn {
    let directory: URL
    let executable: URL

    /// A `mooringctl` that records its arguments, prints `lines` (each
    /// re-encoded compactly, as the CLI prints them), writes `stderr` to
    /// stderr and exits with `code`.
    init(lines: [Data], stderr: String, code: Int32) throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("mooringkit-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        var output = Data()
        for line in lines {
            output.append(try Fixtures.encode(try Fixtures.json(line)))
            output.append(0x0A)
        }
        try output.write(to: directory.appendingPathComponent("stdout"))
        try Data(stderr.utf8).write(to: directory.appendingPathComponent("stderr"))
        executable = directory.appendingPathComponent("mooringctl")
        let script = """
            #!/bin/sh
            printf '%s ' "$@" > '\(directory.path)/arguments'
            cat '\(directory.path)/stdout'
            cat '\(directory.path)/stderr' >&2
            exit \(code)

            """
        try Data(script.utf8).write(to: executable)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
    }

    var arguments: String {
        get throws {
            String(decoding: try Data(contentsOf: directory.appendingPathComponent("arguments")), as: UTF8.self)
        }
    }

    func remove() throws {
        try FileManager.default.removeItem(at: directory)
    }
}

private func collect(_ command: StatusCommand) async -> [StreamEvent] {
    var events: [StreamEvent] = []
    for await event in command.events() {
        events.append(event)
    }
    return events
}

@Suite struct StreamTests {
    @Test func documentsThenTheEndWithTheCommandsMessage() async throws {
        let available = try Fixtures.console("no-deployment")
        let unavailable = try Fixtures.console("no-deployment-router-unavailable")
        let standIn = try StandIn(
            lines: [available, unavailable],
            stderr: "mooringctl: the daemon closed the status stream\n",
            code: 1)
        defer { try? standIn.remove() }
        let events = await collect(StatusCommand(executable: standIn.executable))
        #expect(try standIn.arguments == "status --follow --json ")
        #expect(events.count == 3)
        #expect(events[0] == .status(try ConsoleStatus.decode(line: available)))
        #expect(events[1] == .status(try ConsoleStatus.decode(line: unavailable)))
        #expect(
            events[2]
                == .ended(StreamEnd(exitCode: 1, message: "mooringctl: the daemon closed the status stream")))
    }

    @Test func aDeploymentLineIsRefusedAndTheStreamGoesOn() async throws {
        let standIn = try StandIn(
            lines: [try Fixtures.console("deployed"), try Fixtures.console("no-deployment")],
            stderr: "", code: 0)
        defer { try? standIn.remove() }
        let events = await collect(StatusCommand(executable: standIn.executable))
        #expect(events.count == 3)
        #expect(
            events[0]
                == .refused("The daemon reports a deployment, which this build of Mooring.app does not show yet."))
        guard case .status = events[1] else {
            Issue.record("the second line is not a status")
            return
        }
        #expect(events[2] == .ended(StreamEnd(exitCode: 0, message: "")))
    }

    @Test func aCommandThatCannotStartEndsAtOnce() async throws {
        let missing = URL(fileURLWithPath: "/nonexistent-\(UUID().uuidString)/mooringctl")
        let events = await collect(StatusCommand(executable: missing))
        #expect(events.count == 1)
        guard case .ended(let end) = events.first else {
            Issue.record("no end")
            return
        }
        #expect(end.exitCode == nil)
        #expect(end.message.hasPrefix("cannot start \(missing.path): "))
    }

    @Test func anUnreadableLineIsRefusedWithItsReason() {
        guard case .refused(let message) = StatusCommand.event(for: "{\"no_deployment\":{}}") else {
            Issue.record("not refused")
            return
        }
        #expect(message.hasPrefix("A line from mooringctl could not be read: "))
        #expect(
            StatusCommand.event(for: "{\"no_deployment\":{\"version\":3,\"at\":1,\"router\":{}}}")
                == .refused("The daemon's document is version 3; this build reads version 1."))
    }
}

@Suite @MainActor struct ConsoleModelTests {
    @Test func theModelGoesLiveThenSaysTheStreamEnded() async throws {
        let standIn = try StandIn(
            lines: [try Fixtures.console("no-deployment")],
            stderr: "mooringctl: the daemon closed the status stream\n",
            code: 1)
        defer { try? standIn.remove() }
        let model = ConsoleModel(
            command: StatusCommand(executable: standIn.executable), retryDelay: .seconds(600))
        #expect(model.state == .connecting)
        model.start()
        let deadline = Date().addingTimeInterval(10)
        while Date() < deadline {
            if case .ended = model.state { break }
            try await Task.sleep(for: .milliseconds(20))
        }
        model.stop()
        guard case .ended(let end, let retryAt) = model.state else {
            Issue.record("the stream did not end: \(model.state)")
            return
        }
        #expect(end == StreamEnd(exitCode: 1, message: "mooringctl: the daemon closed the status stream"))
        #expect(retryAt > Date().addingTimeInterval(500))
        #expect(model.status == (try ConsoleStatus.decode(line: try Fixtures.console("no-deployment"))))
        #expect(model.receivedAt != nil)
        #expect(model.refusal == nil)
    }

    @Test func noCommandIsShownAsSuch() {
        let model = ConsoleModel(command: nil, missing: "Contents/MacOS/mooringctl")
        #expect(model.state == .noCommand("Contents/MacOS/mooringctl"))
        model.start()
        #expect(model.state == .noCommand("Contents/MacOS/mooringctl"))
    }

    @Test func eventsChangeTheModelAsDocumented() throws {
        let model = ConsoleModel(command: nil)
        let status = try ConsoleStatus.decode(line: try Fixtures.console("no-deployment"))
        model.apply(.refused("no"))
        #expect(model.refusal == "no")
        model.apply(.status(status))
        #expect(model.state == .live)
        #expect(model.status == status)
        #expect(model.refusal == nil)
    }
}
