// SPDX-License-Identifier: GPL-3.0-or-later

// launchd's record of an agent, read from `launchctl print`: the lines the
// app reads, what they say of the agent's start, and the printouts it
// refuses.

import Testing

@testable import MooringKit

@Suite struct LaunchRecordTests {
    @Test func theRunningDaemonsPrintoutIsRead() throws {
        let record = try LaunchRecord(printed: LaunchPrintouts.runningDaemon)
        #expect(
            record
                == LaunchRecord(
                    state: "running", runs: 1, lastExit: .never, jobState: "running",
                    properties: ["partial import", "keepalive", "runatload", "resolve program", "has LWCR"]))
        #expect(record.condition == .running)
    }

    @Test func theApplyJobsPrintoutAfterARunIsRead() throws {
        let record = try LaunchRecord(printed: LaunchPrintouts.jobAfterARun)
        #expect(
            record
                == LaunchRecord(
                    state: "not running", runs: 15, lastExit: .code(0), jobState: "exited",
                    properties: ["partial import", "resolve program", "has LWCR"]))
        #expect(record.condition == .exited(.code(0)))
    }

    /// The first refused start leaves no exit code; the second, which has
    /// macOS replace the record, ends with 78.
    @Test func aStartRefusedOnceIsToldFromARecordReplaced() throws {
        let daemonOnce = try LaunchRecord(printed: LaunchPrintouts.daemonRefusedOnce)
        #expect(daemonOnce.lastExit == nil)
        #expect(daemonOnce.runs == 1)
        #expect(daemonOnce.condition == .refusedOnce)
        let daemonTwice = try LaunchRecord(printed: LaunchPrintouts.daemonRecordReplaced)
        #expect(daemonTwice.lastExit == .code(78))
        #expect(daemonTwice.condition == .recordReplaced)
        #expect(try LaunchRecord(printed: LaunchPrintouts.jobRefusedOnce).condition == .refusedOnce)
        #expect(try LaunchRecord(printed: LaunchPrintouts.jobRecordReplaced).condition == .recordReplaced)
        // A later refused start ends with 78 again.
        let later = LaunchPrintouts.printout(
            state: "spawn scheduled", runs: 7, lastExit: "78: EX_CONFIG", jobState: "spawn failed",
            properties: "keepalive | needs LWCR update | has LWCR")
        #expect(try LaunchRecord(printed: later).condition == .recordReplaced)
    }

    @Test func anAgentLaunchdHasNotStartedIsIdle() throws {
        let record = try LaunchRecord(printed: LaunchPrintouts.jobIdle)
        #expect(record.runs == 0)
        #expect(record.lastExit == .never)
        #expect(record.condition == .idle)
        // The daemon in the moment before launchd's first start.
        let daemon = LaunchPrintouts.printout(
            state: "spawn scheduled", runs: 0, lastExit: "(never exited)", jobState: nil, properties: nil)
        #expect(try LaunchRecord(printed: daemon).condition == .idle)
    }

    /// The blocks nested in a printout repeat `state`, `runs`, `job state`,
    /// `properties` and `last exit code` further in: the frame of
    /// `printout` has all five, and none is read.
    @Test func onlyTheServicesOwnLinesAreRead() throws {
        let record = try LaunchRecord(
            printed: LaunchPrintouts.printout(
                state: "not running", runs: 3, lastExit: nil, jobState: nil, properties: nil))
        #expect(
            record == LaunchRecord(state: "not running", runs: 3, lastExit: nil, jobState: nil, properties: []))
        // A key printed twice at the service's depth: the first is the
        // service's.
        let twice = "x = {\n\tstate = running\n\truns = 1\n\tstate = waiting\n\truns = 2\n}\n"
        let first = try LaunchRecord(printed: twice)
        #expect(first.state == "running")
        #expect(first.runs == 1)
    }

    @Test func aProgramThatEndedByItselfHasExited() throws {
        // The daemon between two starts after its program ended with 1.
        let ended = LaunchPrintouts.printout(
            state: "spawn scheduled", runs: 3, lastExit: "1", jobState: "exited",
            properties: "keepalive | runatload | has LWCR")
        #expect(try LaunchRecord(printed: ended).condition == .exited(.code(1)))
    }

    @Test func theLastExitIsTheCodeBeforeItsName() {
        #expect(LaunchLastExit(printed: "(never exited)") == .never)
        #expect(LaunchLastExit(printed: "0") == .code(0))
        #expect(LaunchLastExit(printed: "78: EX_CONFIG") == .code(78))
        #expect(LaunchLastExit(printed: "-1: unknown") == .code(-1))
        for other in ["", "EX_CONFIG", "78 EX_CONFIG", "(never exited) ", ": 78", "7x: y"] {
            #expect(LaunchLastExit(printed: other) == .other(other), "\(other)")
        }
    }

    /// A state the app does not know is named with the record's lines, not
    /// taken for one it knows.
    @Test func whatTheAppDoesNotKnowIsNamedWithTheRecordsLines() throws {
        // A start that failed for another reason than the launch constraint.
        let failed = try LaunchRecord(
            printed: LaunchPrintouts.printout(
                state: "not running", runs: 2, lastExit: "78: EX_CONFIG", jobState: "spawn failed",
                properties: "partial import | has LWCR"))
        #expect(failed.condition == nil)
        #expect(
            failed.summary
                == "state = not running, runs = 2, last exit code = 78, job state = spawn failed, "
                + "properties = partial import | has LWCR")
        #expect(LaunchReading(failed) == .unknown(failed.summary))
        // Started, not running, and no job state.
        let bare = try LaunchRecord(
            printed: LaunchPrintouts.printout(
                state: "waiting", runs: 4, lastExit: "(never exited)", jobState: nil, properties: nil))
        #expect(bare.condition == nil)
        #expect(bare.summary == "state = waiting, runs = 4, last exit code = (never exited)")
        // An exit launchd words another way.
        let worded = try LaunchRecord(
            printed: LaunchPrintouts.printout(
                state: "waiting", runs: 4, lastExit: "killed", jobState: "stopped", properties: nil))
        #expect(worded.condition == nil)
        #expect(worded.summary == "state = waiting, runs = 4, last exit code = killed, job state = stopped")
        // 78 from the program itself is an exit, not a refused start.
        let itself = LaunchPrintouts.printout(
            state: "not running", runs: 1, lastExit: "78: EX_CONFIG", jobState: "exited",
            properties: "needs LWCR update")
        #expect(try LaunchRecord(printed: itself).condition == .exited(.code(78)))
    }

    /// A start that never reached the program is a refused one, whatever
    /// `state` says in that moment.
    @Test func aFailedStartShownAsRunningIsRefused() throws {
        let once = LaunchPrintouts.printout(
            state: "running", runs: 1, lastExit: nil, jobState: "spawn failed",
            properties: "keepalive | needs LWCR update | has LWCR")
        #expect(try LaunchRecord(printed: once).condition == .refusedOnce)
        let twice = LaunchPrintouts.printout(
            state: "running", runs: 2, lastExit: "78: EX_CONFIG", jobState: "spawn failed",
            properties: "keepalive | needs LWCR update | has LWCR")
        #expect(try LaunchRecord(printed: twice).condition == .recordReplaced)
        // One refused when its last run had ended with 0, as the apply job
        // is at its first hour after a build installed over a registered
        // one.
        let afterARun = LaunchPrintouts.printout(
            state: "not running", runs: 16, lastExit: "0", jobState: "spawn failed",
            properties: "partial import | needs LWCR update | has LWCR")
        #expect(try LaunchRecord(printed: afterARun).condition == .refusedOnce)
    }

    @Test func aReadingIsTheRecordsConditionOrWhyThereIsNone() throws {
        #expect(LaunchReading(nil) == .notListed)
        #expect(LaunchReading(try LaunchRecord(printed: LaunchPrintouts.runningDaemon)) == .condition(.running))
        #expect(
            LaunchReading(try LaunchRecord(printed: LaunchPrintouts.jobRecordReplaced)) == .condition(.recordReplaced))
    }

    @Test func aPrintoutWithoutTheLinesIsRefused() {
        // What `launchctl print` writes for a service launchd does not list.
        let notListed = "Bad request.\nCould not find service \"com.example.agent\" in domain for user gui: 501\n"
        #expect(throws: LaunchRecordError.notAPrintout(String(notListed.prefix(120)))) {
            try LaunchRecord(printed: notListed)
        }
        #expect(throws: LaunchRecordError.notAPrintout("")) { try LaunchRecord(printed: "") }
        #expect(throws: LaunchRecordError.notAPrintout("\tstate = running\n")) {
            try LaunchRecord(printed: "\tstate = running\n")
        }
        // A block from inside a printout, and a first line that names no
        // service.
        for begun in ["\tx = {\n\tstate = running\n\truns = 1\n}\n", "x {\n\tstate = running\n\truns = 1\n}\n"] {
            #expect(throws: LaunchRecordError.notAPrintout(begun), "\(begun)") {
                try LaunchRecord(printed: begun)
            }
        }
        // Only the first 120 characters of what was printed are kept.
        let long = String(repeating: "x", count: 500)
        #expect(throws: LaunchRecordError.notAPrintout(String(repeating: "x", count: 120))) {
            try LaunchRecord(printed: long)
        }
        #expect(throws: LaunchRecordError.missing("state")) {
            try LaunchRecord(printed: "x = {\n\truns = 1\n}\n")
        }
        #expect(throws: LaunchRecordError.missing("runs")) {
            try LaunchRecord(printed: "x = {\n\tstate = running\n\t\truns = 1\n}\n")
        }
        for runs in ["many", "-1", "", "1 (of 2)"] {
            #expect(throws: LaunchRecordError.unreadable("runs = \(runs)"), "\(runs)") {
                try LaunchRecord(printed: "x = {\n\tstate = running\n\truns = \(runs)\n}\n")
            }
        }
        // Indented otherwise than one tab, or without ` = `, a line is not
        // the service's.
        #expect(throws: LaunchRecordError.missing("state")) {
            try LaunchRecord(printed: "x = {\n state = running\n\tstate: running\n\truns = 1\n}\n")
        }
    }

    @Test func whatTheRecordsAskOfTheOperator() {
        let good: [LaunchReading] = [
            .condition(.running), .condition(.idle), .condition(.exited(.code(0))), .unknown("x"), .notListed,
        ]
        let refused: [LaunchReading] = [.condition(.refusedOnce), .condition(.recordReplaced)]
        for daemon in good {
            for job in good {
                #expect(LaunchAttention(daemon: daemon, job: job) == .nothing, "\(daemon) \(job)")
            }
            for job in refused {
                #expect(LaunchAttention(daemon: daemon, job: job) == .applyJobRefused, "\(daemon) \(job)")
            }
        }
        // A refused daemon comes first: the round that carries it through
        // repairs the job with it.
        for daemon in refused {
            for job in good + refused {
                #expect(LaunchAttention(daemon: daemon, job: job) == .daemonRefused, "\(daemon) \(job)")
            }
        }
    }
}
