// SPDX-License-Identifier: GPL-3.0-or-later

// What `launchctl print` writes for the app's two agents, for the tests of
// the record, of `launchctl` and of the round.
//
// `runningDaemon` and `jobAfterARun` are whole printouts as macOS 27.2
// wrote them on 2026-11-13 for the daemon and the apply job, with the
// record's id, the process id and the per-boot socket path replaced. For an
// agent that macOS refuses only the lines the app reads were kept that day
// (from a throwaway app with the same plist keys), so `printout(...)` puts
// those lines into the frame of a whole printout, between the nested
// blocks, which repeat some of the keys further in.

enum LaunchPrintouts {
    /// The daemon while it runs.
    static let runningDaemon = """
        gui/501/com.bill.mooring.daemon = {
        \tactive count = 1
        \tpath = (submitted by smd.570)
        \ttype = Submitted
        \tmanaged_by = com.apple.xpc.ServiceManagement
        \tstate = running

        \tprogram identifier = Contents/MacOS/mooringctl (mode: 2)
        \tparent bundle identifier = com.bill.mooring
        \tparent bundle version = 1
        \tBTM uuid = 00000000-0000-4000-8000-000000000001
        \targuments = {
        \t\tmooringctl
        \t\tdaemon
        \t}

        \tinherited environment = {
        \t\tSSH_AUTH_SOCK => /var/run/com.apple.launchd.XXXXXXXXXX/Listeners
        \t}

        \tdefault environment = {
        \t\tPATH => /usr/bin:/bin:/usr/sbin:/sbin
        \t}

        \tenvironment = {
        \t\tOSLogRateLimit => 64
        \t\tXPC_SERVICE_NAME => com.bill.mooring.daemon
        \t}

        \tLWCR = {
        \t\t"reqs" => {
        \t\t\t"cdhash" => {
        \t\t\t\t"$in" => [
        \t\t\t\t\t0 = \t\t\t\t]
        \t\t\t}
        \t\t}
        \t\t"vers" => 1
        \t\t"comp" => 1
        \t\t"ccat" => 0
        \t}

        \tdomain = gui/501 [100015]
        \tasid = 100015
        \tminimum runtime = 60
        \texit timeout = 5
        \truns = 1
        \tpid = 4242
        \timmediate reason = speculative
        \tforks = 2047
        \texecs = 1
        \tinitialized = 1
        \ttrampolined = 1
        \tstarted suspended = 0
        \tproxy started suspended = 0
        \tchecked allocations = 0 (queried = 1)
        \tchecked allocations reason = no host
        \tchecked allocations flags = 0x0
        \tlast exit code = (never exited)

        \tresource coalition = {
        \t\tID = 175057
        \t\ttype = resource
        \t\tstate = active
        \t\tactive count = 1
        \t\tname = com.bill.mooring.daemon
        \t}

        \tjetsam coalition = {
        \t\tID = 175058
        \t\ttype = jetsam
        \t\tstate = active
        \t\tactive count = 1
        \t\tname = com.bill.mooring.daemon
        \t}

        \tspawn type = daemon (3)
        \tjetsam priority = 40
        \tjetsam memory limit (active) = (unlimited)
        \tjetsam memory limit (inactive) = (unlimited)
        \tjetsamproperties category = daemon
        \tsubmitted job. ignore execute allowed
        \tjetsam thread limit = 32
        \tcpumon = default
        \tresource limits = {
        \t\tmaxfiles (soft) => 16384
        \t}

        \tjob state = running
        \tsanitizer flags = 0x0

        \tproperties = partial import | keepalive | runatload | resolve program | has LWCR
        }

        """

    /// The apply job after fifteen hourly runs, the last one ended with 0.
    static let jobAfterARun = """
        gui/501/com.bill.mooring.apply = {
        \tactive count = 0
        \tpath = (submitted by smd.570)
        \ttype = Submitted
        \tmanaged_by = com.apple.xpc.ServiceManagement
        \tstate = not running

        \tprogram identifier = Contents/MacOS/mooringctl (mode: 2)
        \tparent bundle identifier = com.bill.mooring
        \tparent bundle version = 1
        \tBTM uuid = 00000000-0000-4000-8000-000000000002
        \targuments = {
        \t\tmooringctl
        \t\tapply
        \t\t--pending
        \t}

        \tinherited environment = {
        \t\tSSH_AUTH_SOCK => /var/run/com.apple.launchd.XXXXXXXXXX/Listeners
        \t}

        \tdefault environment = {
        \t\tPATH => /usr/bin:/bin:/usr/sbin:/sbin
        \t}

        \tenvironment = {
        \t\tOSLogRateLimit => 64
        \t\tXPC_SERVICE_NAME => com.bill.mooring.apply
        \t}

        \tLWCR = {
        \t\t"reqs" => {
        \t\t\t"cdhash" => {
        \t\t\t\t"$in" => [
        \t\t\t\t\t0 = \t\t\t\t]
        \t\t\t}
        \t\t}
        \t\t"vers" => 1
        \t\t"comp" => 1
        \t\t"ccat" => 0
        \t}

        \tdomain = gui/501 [100015]
        \tasid = 100015
        \tminimum runtime = 10
        \texit timeout = 5
        \truns = 15
        \tlast exit code = 0

        \tevent triggers = {
        \t\tcom.bill.mooring.apply.268435474 => {
        \t\t\tkeepalive = 0
        \t\t\tservice = com.bill.mooring.apply
        \t\t\tstream = com.apple.launchd.calendarinterval
        \t\t\tmonitor = com.apple.UserEventAgent-Aqua
        \t\t\tdescriptor = {
        \t\t\t\t"Minute" => 20
        \t\t\t}
        \t\t}
        \t}

        \tevent channels = {
        \t\t"com.apple.launchd.calendarinterval" = {
        \t\t\tport = 0x117693
        \t\t\tactive = 0
        \t\t\tmanaged = 1
        \t\t\treset = 0
        \t\t\thide = 0
        \t\t\twatching = 1
        \t\t}
        \t}

        \tresource coalition = {
        \t\tID = 175427
        \t\ttype = resource
        \t\tstate = active
        \t\tactive count = 1
        \t\tname = com.bill.mooring.apply
        \t}

        \tjetsam coalition = {
        \t\tID = 175428
        \t\ttype = jetsam
        \t\tstate = active
        \t\tactive count = 1
        \t\tname = com.bill.mooring.apply
        \t}

        \tspawn type = daemon (3)
        \tjetsam priority = 40
        \tjetsam memory limit (active) = (unlimited)
        \tjetsam memory limit (inactive) = (unlimited)
        \tjetsamproperties category = daemon
        \tsubmitted job. ignore execute allowed
        \tjetsam thread limit = 32
        \tcpumon = default
        \tjob state = exited
        \tsanitizer flags = 0x0

        \tproperties = partial import | resolve program | has LWCR
        }

        """

    /// The properties of the daemon's record and of the job's.
    static let daemonProperties = "partial import | keepalive | runatload | resolve program"
    static let jobProperties = "partial import | resolve program"

    /// A printout with the given lines of the service's own, in the frame
    /// of a whole one: the blocks nested in it say `state = active` and
    /// name a process of their own, further in.
    static func printout(
        state: String, runs: Int, lastExit: String?, jobState: String?, properties: String?
    ) -> String {
        var lines = [
            "gui/501/com.example.agent = {",
            "\tactive count = 0",
            "\tstate = \(state)",
            "",
            "\tprogram identifier = Contents/MacOS/mooringctl (mode: 2)",
            "\tsemaphores = {",
            "\t\tpid = 1",
            "\t\truns = 99",
            "\t}",
            "",
            "\truns = \(runs)",
        ]
        if let lastExit {
            lines.append("\tlast exit code = \(lastExit)")
        }
        lines += [
            "",
            "\tresource coalition = {",
            "\t\tstate = active",
            "\t\tjob state = running",
            "\t\tproperties = nested",
            "\t\tlast exit code = 9",
            "\t}",
            "",
        ]
        if let jobState {
            lines.append("\tjob state = \(jobState)")
        }
        if let properties {
            lines += ["", "\tproperties = \(properties)"]
        }
        lines += ["}", ""]
        return lines.joined(separator: "\n")
    }

    /// The daemon after macOS refused its first start (2026-11-13,
    /// 09:56:12 UTC).
    static let daemonRefusedOnce = printout(
        state: "spawn scheduled", runs: 1, lastExit: nil, jobState: "spawn failed",
        properties: "\(daemonProperties) | needs LWCR update | has LWCR")

    /// The daemon after launchd's second start, which had macOS replace its
    /// record (09:57:10).
    static let daemonRecordReplaced = printout(
        state: "spawn scheduled", runs: 2, lastExit: "78: EX_CONFIG", jobState: "spawn failed",
        properties: "\(daemonProperties) | needs LWCR update | has LWCR")

    /// The job that launchd has not started since it was registered
    /// (09:57:40).
    static let jobIdle = printout(
        state: "not running", runs: 0, lastExit: "(never exited)", jobState: "uninitialized",
        properties: "\(jobProperties) | has LWCR")

    /// The job after its first start by hand, which macOS refused
    /// (09:56:12).
    static let jobRefusedOnce = printout(
        state: "not running", runs: 1, lastExit: nil, jobState: "spawn failed",
        properties: "\(jobProperties) | needs LWCR update | has LWCR")

    /// The job after its second start by hand (09:56:32).
    static let jobRecordReplaced = printout(
        state: "not running", runs: 2, lastExit: "78: EX_CONFIG", jobState: "spawn failed",
        properties: "\(jobProperties) | needs LWCR update | has LWCR")
}
