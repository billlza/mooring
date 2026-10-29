// SPDX-License-Identifier: GPL-3.0-or-later

// A stand-in `mooringctl` for the command runners' tests: a shell script
// that records its arguments, prints what it is given and exits or waits.

import Foundation

/// A directory holding a stand-in `mooringctl` and its inputs.
struct StandIn {
    let directory: URL
    let executable: URL

    /// A `mooringctl` that records its arguments and its process id (each
    /// run appends them), prints `stdout`, writes `stderr` to stderr, then
    /// exits with `code`, or with `waits` sleeps in its own process instead.
    /// With `laterRunsWait`, every run after the first sleeps at once and
    /// prints nothing, as a follower waiting for a daemon's first status.
    init(
        stdout: Data, stderr: Data = Data(), code: Int32 = 0, waits: Bool = false, laterRunsWait: Bool = false
    ) throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("mooringkit-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try stdout.write(to: directory.appendingPathComponent("stdout"))
        try stderr.write(to: directory.appendingPathComponent("stderr"))
        executable = directory.appendingPathComponent("mooringctl")
        let end = waits ? "exec sleep 60" : "exit \(code)"
        let later = laterRunsWait ? "[ \"$(grep -c '' '\(directory.path)/runs')\" -gt 1 ] && exec sleep 60" : ""
        let script = """
            #!/bin/sh
            printf '%s ' "$@" > '\(directory.path)/arguments'
            echo $$ >> '\(directory.path)/runs'
            \(later)
            cat '\(directory.path)/stdout'
            cat '\(directory.path)/stderr' >&2
            \(end)

            """
        try Data(script.utf8).write(to: executable)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
    }

    /// A stand-in printing `lines`, each re-encoded compactly as the CLI
    /// prints them and ended with a newline.
    init(lines: [Data], stderr: String = "", code: Int32 = 0, waits: Bool = false, laterRunsWait: Bool = false)
        throws
    {
        var output = Data()
        for line in lines {
            output.append(try Fixtures.encode(try Fixtures.json(line)))
            output.append(0x0A)
        }
        try self.init(
            stdout: output, stderr: Data(stderr.utf8), code: code, waits: waits, laterRunsWait: laterRunsWait)
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
