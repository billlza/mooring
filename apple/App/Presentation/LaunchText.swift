// SPDX-License-Identifier: GPL-3.0-or-later

// How the console words the start of Mooring's two launch agents (design
// §5.1): what the round that carries a start through is doing, why one did
// not get there, and what `launchctl` gave instead of an answer. The words
// say what MooringKit decided; they decide nothing. The times in them are
// the round's own.

import MooringKit
import SwiftUI

extension LaunchRoundPhase {
    /// The line in the menu while a round runs.
    var menuLine: String {
        switch self {
        case .starting, .startingAgain: String(localized: "Daemon: starting…")
        case .newBuild: String(localized: "Daemon: a new build; waiting for macOS, about a minute and a half")
        case .registeringAgain: String(localized: "Daemon: being registered again")
        case .repairingJob: String(localized: "Apply job: being repaired, up to a minute")
        }
    }

    /// The banner's title while a round runs.
    var title: String {
        switch self {
        case .starting: String(localized: "Starting Mooring's daemon")
        case .newBuild, .registeringAgain, .startingAgain: String(localized: "Starting a new build of Mooring")
        case .repairingJob: String(localized: "Repairing the nightly apply job")
        }
    }

    /// What the round is doing, under the title.
    var detail: String {
        switch self {
        case .starting:
            String(localized: "Waiting for launchd to start it.")
        case .newBuild:
            String(
                localized:
                    "macOS refused the start, as it does after a new build is installed until its record of the registration is replaced. That happens at the daemon's second start, which launchd makes a minute after the first; meanwhile the app starts the nightly apply job twice, for the same reason. Then, 20 s later, it registers both again: about a minute and a half in all. Nothing needs doing."
            )
        case .registeringAgain:
            String(localized: "macOS has replaced its records. Registering the daemon and the apply job again.")
        case .startingAgain:
            String(localized: "Registered again. Waiting for launchd to start the daemon.")
        case .repairingJob:
            String(
                localized:
                    "macOS replaces its record of the job at the job's second refused start, which the app makes about 20 s after it saw the first. Then, 20 s later, it registers the daemon and the job again, which stops the daemon for a few seconds and restarts the exit with it."
            )
        }
    }
}

extension LaunchRoundFailure {
    /// Why the round did not get there, or what kept a reading of launchd's
    /// records from telling anything, in the user's language.
    var text: String {
        let timing = LaunchRoundPlan.Timing()
        return switch self {
        case .notListed(.daemon):
            String(localized: "launchd does not list the daemon.")
        case .notListed(.applyJob):
            String(localized: "launchd does not list the apply job.")
        case .daemonNotStarted:
            String(localized: "launchd did not start the daemon within \(timing.settle.components.seconds) s.")
        case .daemonEnded(.code(let code)?):
            String(
                localized:
                    "The daemon started and ended by itself with exit code \(code); its log (~/Library/Logs/Mooring/daemon.log) says why."
            )
        case .daemonEnded:
            String(
                localized:
                    "The daemon started and ended by itself; its log (~/Library/Logs/Mooring/daemon.log) says why.")
        case .startIgnored:
            String(localized: "launchd was asked to start the apply job, and its record of the job did not change.")
        case .notReplaced(.daemon):
            String(
                localized:
                    "macOS refused the daemon and did not replace its record of it within \(timing.replacement.components.seconds) s."
            )
        case .notReplaced(.applyJob):
            String(
                localized:
                    "macOS refused the apply job at \(timing.jobStarts) starts by hand and did not replace its record of it."
            )
        case .stillRefused(.daemon):
            String(
                localized: "macOS still refuses the daemon after it was registered again \(timing.registrations) times."
            )
        case .stillRefused(.applyJob):
            String(
                localized:
                    "macOS still refuses the apply job after it was registered again \(timing.registrations) times.")
        case .unknownState(.daemon, let lines):
            String(localized: "launchd's record of the daemon is in a state this build does not know: \(lines)")
        case .unknownState(.applyJob, let lines):
            String(localized: "launchd's record of the apply job is in a state this build does not know: \(lines)")
        case .tookTooLong:
            String(localized: "It took longer than \(timing.whole.components.seconds) s.")
        case .launchctl(let failure):
            failure.text
        case .registration(let why):
            String(localized: "The daemon and the apply job could not be registered again: \(why)")
        }
    }
}

extension LaunchctlFailure {
    /// What `launchctl` gave instead of an answer, in the user's language,
    /// then its own words.
    var text: String {
        switch self {
        case .ended(let arguments, let end):
            let command = arguments.joined(separator: " ")
            let how =
                switch end.reason {
                case .exited(let code): String(localized: "`launchctl \(command)` exited with code \(code).")
                case .signalled(let signal): String(localized: "`launchctl \(command)` was ended by signal \(signal).")
                case .notStarted(let why): String(localized: "launchctl could not be started: \(why)")
                }
            return end.message.isEmpty ? how : "\(how) \(end.message)"
        case .tooLong(let arguments):
            return String(
                localized:
                    "`launchctl \(arguments.joined(separator: " "))` printed more than \(Launchctl.outputLimit / 1024) KiB, so the app stopped reading it."
            )
        case .overdue(let arguments):
            return String(
                localized:
                    "`launchctl \(arguments.joined(separator: " "))` had not ended after \(Launchctl.timeLimit.components.seconds) s, so the app ended it."
            )
        case .unreadable(let service, .notAPrintout(let begins)):
            return String(
                localized:
                    "What launchctl printed for \(service) is not a record this build reads. It begins: \(begins)")
        case .unreadable(let service, .missing(let key)):
            return String(localized: "The record launchctl printed for \(service) has no “\(key)” line.")
        case .unreadable(let service, .unreadable(let line)):
            return String(
                localized: "The record launchctl printed for \(service) has a line this build cannot read: \(line)")
        }
    }
}
