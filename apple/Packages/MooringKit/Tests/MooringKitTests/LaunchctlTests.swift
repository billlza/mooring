// SPDX-License-Identifier: GPL-3.0-or-later

// `launchctl` for the app's own agents, against a stand-in: what it is
// asked, and that every answer but a record, "not listed" and a start
// accepted is a failure that carries `launchctl`'s own words.

import Darwin
import Foundation
import Testing

@testable import MooringKit

@Suite(.timeLimit(.minutes(1))) struct LaunchctlTests {
    private let label = "com.example.agent"

    private func launchctl(_ standIn: StandIn) -> Launchctl {
        Launchctl(executable: standIn.executable, uid: 501)
    }

    @Test func theUsersOwnDomainIsAsked() {
        #expect(Launchctl().domain == "gui/\(getuid())")
        #expect(Launchctl().executable.path == "/bin/launchctl")
        #expect(Launchctl(uid: 502).service(label) == "gui/502/com.example.agent")
    }

    @Test func aListedServicesPrintoutIsRead() async throws {
        let standIn = try StandIn(stdout: Data(LaunchPrintouts.jobAfterARun.utf8))
        defer { try? standIn.remove() }
        let record = try await launchctl(standIn).record(of: label)
        #expect(try standIn.arguments == "print gui/501/com.example.agent ")
        #expect(record == (try LaunchRecord(printed: LaunchPrintouts.jobAfterARun)))
    }

    /// launchd answers 113 for a service it does not list, with words on
    /// both streams that are not read.
    @Test func aServiceLaunchdDoesNotListHasNoRecord() async throws {
        let standIn = try StandIn(
            stdout: Data("Bad request.\n".utf8),
            stderr: Data("Could not find service \"com.example.agent\" in domain for user gui: 501\n".utf8),
            code: 113)
        defer { try? standIn.remove() }
        #expect(try await launchctl(standIn).record(of: label) == nil)
    }

    @Test func anyOtherEndOfPrintIsAFailureWithLaunchctlsWords() async throws {
        let standIn = try StandIn(
            stdout: Data(LaunchPrintouts.jobAfterARun.utf8), stderr: Data("Unrecognized target specifier.\n".utf8),
            code: 64)
        defer { try? standIn.remove() }
        let failure = LaunchctlFailure.ended(
            arguments: ["print", "gui/501/com.example.agent"],
            StreamEnd(reason: .exited(64), message: "Unrecognized target specifier."))
        await #expect(throws: failure) { try await launchctl(standIn).record(of: label) }
    }

    @Test func aPrintoutThisBuildDoesNotReadIsRefused() async throws {
        let standIn = try StandIn(stdout: Data("gui/501/com.example.agent = {\n\truns = 1\n}\n".utf8))
        defer { try? standIn.remove() }
        let failure = LaunchctlFailure.unreadable(service: "gui/501/com.example.agent", .missing("state"))
        await #expect(throws: failure) { try await launchctl(standIn).record(of: label) }
    }

    @Test func outputPastTheBoundIsRefusedWhole() async throws {
        #expect(Launchctl.outputLimit == 262_144)
        let standIn = try StandIn(stdout: Data(repeating: 0x78, count: Launchctl.outputLimit + 1))
        defer { try? standIn.remove() }
        let failure = LaunchctlFailure.tooLong(arguments: ["print", "gui/501/com.example.agent"])
        await #expect(throws: failure) { try await launchctl(standIn).record(of: label) }
        // A printout of exactly the bound is read.
        let whole = try StandIn(
            stdout: Data(
                (LaunchPrintouts.jobAfterARun
                    + String(repeating: "\n", count: Launchctl.outputLimit - LaunchPrintouts.jobAfterARun.utf8.count))
                    .utf8))
        defer { try? whole.remove() }
        #expect(try await launchctl(whole).record(of: label)?.runs == 15)
    }

    /// launchd answers a start with 0 and no words, whether the start then
    /// succeeds or is refused.
    @Test func aStartNamesTheServiceAndIsAccepted() async throws {
        let standIn = try StandIn(stdout: Data())
        defer { try? standIn.remove() }
        try await launchctl(standIn).kickstart(label)
        #expect(try standIn.arguments == "kickstart gui/501/com.example.agent ")
        #expect(standIn.runs.count == 1)
    }

    @Test func aStartThatLaunchdDoesNotAcceptIsAFailure() async throws {
        let standIn = try StandIn(
            stdout: Data(), stderr: Data("Could not find service \"com.example.agent\"\n".utf8), code: 113)
        defer { try? standIn.remove() }
        let failure = LaunchctlFailure.ended(
            arguments: ["kickstart", "gui/501/com.example.agent"],
            StreamEnd(reason: .exited(113), message: "Could not find service \"com.example.agent\""))
        await #expect(throws: failure) { try await launchctl(standIn).kickstart(label) }
    }

    /// launchd answers at once or, wedged, not at all: a run still going at
    /// the time limit is ended, and what it had printed is no record.
    @Test func aRunStillGoingAtTheTimeLimitIsEnded() async throws {
        #expect(Launchctl.timeLimit == .seconds(10))
        #expect(Launchctl().timeLimit == .seconds(10))
        // It prints a whole record, then stays for a minute.
        let standIn = try StandIn(stdout: Data(LaunchPrintouts.jobAfterARun.utf8), waits: true)
        defer { try? standIn.remove() }
        let launchctl = Launchctl(executable: standIn.executable, uid: 501, timeLimit: .seconds(3))
        let began = ContinuousClock.now
        let print = LaunchctlFailure.overdue(arguments: ["print", "gui/501/com.example.agent"])
        await #expect(throws: print) { try await launchctl.record(of: label) }
        // At its own limit: not at the minute the stand-in stays for, nor
        // at the 10 s of a `Launchctl` that is given no limit.
        let took = ContinuousClock.now - began
        #expect(took >= .seconds(3) && took < .seconds(6), "\(took)")
        let start = LaunchctlFailure.overdue(arguments: ["kickstart", "gui/501/com.example.agent"])
        await #expect(throws: start) { try await launchctl.kickstart(label) }
        let runs = standIn.runs
        #expect(runs.count == 2)
        for pid in runs {
            #expect(kill(pid, 0) != 0, "the stand-in \(pid) still runs")
        }
    }

    /// A run that ends by itself within the limit is read whole, and is not
    /// ended: its own exit code comes back.
    @Test func aRunWithinTheTimeLimitIsLeftToEnd() async throws {
        let standIn = try StandIn(
            stdout: Data(), stderr: Data("Could not find service \"com.example.agent\"\n".utf8), code: 113)
        defer { try? standIn.remove() }
        let launchctl = Launchctl(executable: standIn.executable, uid: 501, timeLimit: .seconds(30))
        #expect(try await launchctl.record(of: label) == nil)
    }

    @Test func aMissingLaunchctlIsNotStarted() async throws {
        let missing = URL(fileURLWithPath: "/nonexistent/launchctl-\(UUID().uuidString)")
        let launchctl = Launchctl(executable: missing, uid: 501)
        do {
            _ = try await launchctl.record(of: label)
            Issue.record("a missing launchctl gave a record")
        } catch LaunchctlFailure.ended(let arguments, let end) {
            #expect(arguments == ["print", "gui/501/com.example.agent"])
            guard case .notStarted(let why) = end.reason else {
                Issue.record("ended as \(end.reason)")
                return
            }
            #expect(!why.isEmpty)
            #expect(end.message.isEmpty)
        }
        await #expect(throws: LaunchctlFailure.self) { try await launchctl.kickstart(label) }
    }
}
