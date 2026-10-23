// SPDX-License-Identifier: GPL-3.0-or-later

// The command runner and the model, against a stand-in `mooringctl`: a
// shell script that prints fixture lines and an error, and exits or waits.

import Darwin
import Foundation
import Testing

@testable import MooringKit

/// A directory holding a stand-in `mooringctl` and its inputs.
private struct StandIn {
    let directory: URL
    let executable: URL

    /// A `mooringctl` that records its arguments and its process id (each
    /// run appends them), prints `stdout`, writes `stderr` to stderr, then
    /// exits with `code`, or with `waits` sleeps in its own process instead.
    init(stdout: Data, stderr: Data = Data(), code: Int32 = 0, waits: Bool = false) throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("mooringkit-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try stdout.write(to: directory.appendingPathComponent("stdout"))
        try stderr.write(to: directory.appendingPathComponent("stderr"))
        executable = directory.appendingPathComponent("mooringctl")
        let end = waits ? "exec sleep 60" : "exit \(code)"
        let script = """
            #!/bin/sh
            printf '%s ' "$@" > '\(directory.path)/arguments'
            echo $$ >> '\(directory.path)/runs'
            cat '\(directory.path)/stdout'
            cat '\(directory.path)/stderr' >&2
            \(end)

            """
        try Data(script.utf8).write(to: executable)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
    }

    /// A stand-in printing `lines`, each re-encoded compactly as the CLI
    /// prints them and ended with a newline.
    init(lines: [Data], stderr: String = "", code: Int32 = 0, waits: Bool = false) throws {
        var output = Data()
        for line in lines {
            output.append(try Fixtures.encode(try Fixtures.json(line)))
            output.append(0x0A)
        }
        try self.init(stdout: output, stderr: Data(stderr.utf8), code: code, waits: waits)
    }

    var arguments: String {
        get throws {
            String(decoding: try Data(contentsOf: directory.appendingPathComponent("arguments")), as: UTF8.self)
        }
    }

    /// The process id of each run so far.
    var runs: [pid_t] {
        let text = (try? String(contentsOf: directory.appendingPathComponent("runs"), encoding: .utf8)) ?? ""
        return text.split(separator: "\n").compactMap { pid_t($0) }
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

/// Whether a process with this id is running.
private func running(_ pid: pid_t) -> Bool {
    kill(pid, 0) == 0
}

@Suite(.timeLimit(.minutes(1))) struct StreamTests {
    @Test func documentsThenTheEndWithTheCommandsMessage() async throws {
        let available = try Fixtures.console("no-deployment")
        let unavailable = try Fixtures.console("no-deployment-router-unavailable")
        let standIn = try StandIn(
            lines: [available, unavailable],
            stderr: "mooringctl: the daemon closed the status stream\n",
            code: 1)
        defer { try? standIn.remove() }
        let events = await collect(StatusCommand(executable: standIn.executable))
        #expect(try standIn.arguments == "status --follow --json --until-parent-exits ")
        #expect(events.count == 3)
        #expect(events[0] == .status(try ConsoleStatus.decode(line: available)))
        #expect(events[1] == .status(try ConsoleStatus.decode(line: unavailable)))
        #expect(
            events[2]
                == .ended(
                    StreamEnd(reason: .exited(1), message: "mooringctl: the daemon closed the status stream")))
    }

    /// A deployment's line is shown as one, and a line of another version
    /// is refused while the stream goes on.
    @Test func aDeploymentLineIsShownAndAnotherVersionRefused() async throws {
        let deployed = try Fixtures.console("deployed")
        let later = Data(
            String(decoding: deployed, as: UTF8.self)
                .replacingOccurrences(of: "\"version\": 1", with: "\"version\": 2").utf8)
        let standIn = try StandIn(lines: [deployed, later, try Fixtures.console("no-deployment")])
        defer { try? standIn.remove() }
        let events = await collect(StatusCommand(executable: standIn.executable))
        #expect(events.count == 4)
        guard case .status(.deployed(let status)) = events[0] else {
            Issue.record("the first line is not a deployment's status: \(events)")
            return
        }
        #expect(status.nodes.count == 2)
        #expect(events[1] == .refused(.unsupportedVersion(2)))
        guard case .status(.noDeployment) = events[2] else {
            Issue.record("the third line is not an undeployed status")
            return
        }
        #expect(events[3] == .ended(StreamEnd(reason: .exited(0), message: "")))
    }

    @Test func aCommandThatCannotStartEndsAtOnce() async throws {
        let missing = URL(fileURLWithPath: "/nonexistent-\(UUID().uuidString)/mooringctl")
        let events = await collect(StatusCommand(executable: missing))
        #expect(events.count == 1)
        guard case .ended(let end) = events.first, case .notStarted(let why) = end.reason else {
            Issue.record("not ended as not started: \(events)")
            return
        }
        #expect(!why.isEmpty)
        #expect(end.message.isEmpty)
    }

    @Test func anUnreadableLineIsRefusedWithItsReason() {
        guard case .refused(.unreadable(let why)) = StatusCommand.event(for: Array("{\"no_deployment\":{}}".utf8))
        else {
            Issue.record("not refused as unreadable")
            return
        }
        #expect(!why.isEmpty)
        #expect(
            StatusCommand.event(for: Array("{\"no_deployment\":{\"version\":3,\"at\":1,\"router\":{}}}".utf8))
                == .refused(.unsupportedVersion(3)))
    }

    /// Lines end at 0x0A bytes only, as the CLI writes them: a carrier
    /// name holding U+2028 or NEL, which a text line reader would split,
    /// is one line and one status.
    @Test func linesEndAtNewlineBytesOnly() async throws {
        let line = String(decoding: try Fixtures.console("no-deployment"), as: UTF8.self)
        #expect(line.contains("\"3 UK\""))
        let named = line.replacingOccurrences(of: "\"3 UK\"", with: "\"3\u{2028}U\u{0085}K\"")
        let compact = try Fixtures.encode(try Fixtures.json(Data(named.utf8)))
        #expect(compact.contains(Data("\u{2028}".utf8)))
        let standIn = try StandIn(stdout: compact + Data([0x0A]))
        defer { try? standIn.remove() }
        let events = await collect(StatusCommand(executable: standIn.executable))
        #expect(events.count == 2)
        guard case .status(let status) = events.first, case .available(_, let router) = status.router,
            case .attached(let radio) = router.radio
        else {
            Issue.record("not one status: \(events)")
            return
        }
        #expect(radio.network == "3\u{2028}U\u{0085}K")
    }

    /// A last line without its newline (the command stopped part way
    /// through writing it) is refused, even when it would read as a
    /// document.
    @Test func aLastLineWithoutItsNewlineIsRefused() async throws {
        let line = try Fixtures.encode(try Fixtures.json(try Fixtures.console("no-deployment")))
        let events = try await collectLines(line)
        #expect(events == [.refused(.unreadable("the output ended within a line"))])
    }

    /// A line beyond the CLI's own bound is refused, and the command is
    /// ended rather than read on.
    @Test func aLineBeyondTheBoundEndsTheStream() async throws {
        // It stays running after the line, so only the app can end it.
        let standIn = try StandIn(
            stdout: Data(repeating: 0x78, count: StatusCommand.lineLimit + 10), waits: true)
        defer { try? standIn.remove() }
        let events = await collect(StatusCommand(executable: standIn.executable))
        #expect(events.first == .refused(.tooLong))
        guard case .ended(let end) = events.last else {
            Issue.record("no end: \(events)")
            return
        }
        #expect(end.reason == .signalled(SIGTERM), "\(end)")
        #expect(events.count == 2)
        // A line of exactly the bound, its newline included, is read (and
        // refused for what it holds); one byte more is too long.
        let atBound = try await collectLines(
            Data(repeating: 0x20, count: StatusCommand.lineLimit - 1) + Data([0x0A]))
        guard atBound.count == 1, case .refused(.unreadable) = atBound[0] else {
            Issue.record("the line at the bound was not read: \(atBound)")
            return
        }
        let overBound = try await collectLines(
            Data(repeating: 0x20, count: StatusCommand.lineLimit) + Data([0x0A]))
        #expect(overBound == [.refused(.tooLong)])
    }

    /// A command that writes far more than the kept stderr neither blocks
    /// nor makes the message longer than the limit.
    @Test func muchStderrIsDrainedAndCut() async throws {
        let standIn = try StandIn(
            stdout: Data(), stderr: Data(repeating: 0x65, count: 100 * 1024), code: 3)
        defer { try? standIn.remove() }
        let events = await collect(StatusCommand(executable: standIn.executable))
        guard case .ended(let end) = events.last, events.count == 1 else {
            Issue.record("not one end: \(events)")
            return
        }
        #expect(end.reason == .exited(3))
        #expect(end.message.utf8.count == StatusCommand.stderrLimit)
    }

    /// Ending the iteration early terminates the command.
    @Test func endingTheIterationTerminatesTheCommand() async throws {
        let standIn = try StandIn(lines: [try Fixtures.console("no-deployment")], waits: true)
        defer { try? standIn.remove() }
        for await event in StatusCommand(executable: standIn.executable).events() {
            guard case .status = event else {
                Issue.record("not a status: \(event)")
                return
            }
            break
        }
        let pid = try #require(standIn.runs.first)
        let met1 = try await eventually { !running(pid) }
        #expect(met1)
    }

    private func collectLines(_ stdout: Data) async throws -> [StreamEvent] {
        let standIn = try StandIn(stdout: stdout)
        defer { try? standIn.remove() }
        return Array(await collect(StatusCommand(executable: standIn.executable)).dropLast())
    }
}

@Suite(.timeLimit(.minutes(1))) @MainActor struct ConsoleModelTests {
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
        let ended = try await eventually {
            if case .ended = model.state { true } else { false }
        }
        #expect(ended)
        guard case .ended(let end, let retryAt) = model.state else {
            Issue.record("the stream did not end: \(model.state)")
            return
        }
        #expect(end == StreamEnd(reason: .exited(1), message: "mooringctl: the daemon closed the status stream"))
        #expect(retryAt > Date().addingTimeInterval(500))
        #expect(model.status == (try ConsoleStatus.decode(line: try Fixtures.console("no-deployment"))))
        model.stop()
        #expect(model.state == .stopped)
    }

    /// After the command ends the model starts it again, after the retry
    /// delay, fractions of a second included.
    @Test func theCommandIsStartedAgainAfterTheDelay() async throws {
        let standIn = try StandIn(lines: [], stderr: "mooringctl: the Mooring daemon is not running\n", code: 1)
        defer { try? standIn.remove() }
        let model = ConsoleModel(
            command: StatusCommand(executable: standIn.executable), retryDelay: .milliseconds(150))
        model.start()
        let waiting = try await eventually {
            if case .ended(_, let retryAt) = model.state {
                retryAt.timeIntervalSinceNow < 0.15 && retryAt.timeIntervalSinceNow > 0
            } else { false }
        }
        #expect(waiting)
        let met2 = try await eventually { standIn.runs.count >= 3 }
        #expect(met2)
        model.stop()
    }

    /// Stopping the model, or releasing it, terminates the command, even
    /// while its stream is silent.
    @Test func stoppingOrReleasingTheModelTerminatesTheCommand() async throws {
        let standIn = try StandIn(lines: [try Fixtures.console("no-deployment")], waits: true)
        defer { try? standIn.remove() }
        let model = ConsoleModel(command: StatusCommand(executable: standIn.executable))
        model.start()
        let met3 = try await eventually { model.state == .live }
        #expect(met3)
        let first = try #require(standIn.runs.first)
        model.stop()
        #expect(model.state == .stopped)
        let met4 = try await eventually { !running(first) }
        #expect(met4)

        var released: ConsoleModel? = ConsoleModel(command: StatusCommand(executable: standIn.executable))
        released?.start()
        let met5 = try await eventually { released?.state == .live }
        #expect(met5)
        let second = try #require(standIn.runs.last)
        #expect(second != first)
        released = nil
        let met6 = try await eventually { !running(second) }
        #expect(met6)
    }

    @Test func noCommandIsShownAsSuch() {
        let model = ConsoleModel(command: nil, missing: "Contents/MacOS/mooringctl")
        #expect(model.state == .noCommand("Contents/MacOS/mooringctl"))
        model.start()
        #expect(model.state == .noCommand("Contents/MacOS/mooringctl"))
    }

    /// A refused line leaves the last document on screen, but not as live;
    /// the next document makes the stream live again.
    @Test func aRefusedLineIsNotLive() throws {
        let model = ConsoleModel(command: nil)
        let status = try ConsoleStatus.decode(line: try Fixtures.console("no-deployment"))
        model.apply(.status(status))
        #expect(model.state == .live)
        model.apply(.refused(.unsupportedVersion(2)))
        #expect(model.state == .refusing(.unsupportedVersion(2)))
        #expect(model.status == status)
        model.apply(.status(status))
        #expect(model.state == .live)
    }
}
