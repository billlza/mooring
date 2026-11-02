// SPDX-License-Identifier: GPL-3.0-or-later

// The reads the status stream and the history command share, where no
// command reaches them: a read that fails is an error, never the end of
// the output, and stderr that cannot be read says so.

import Foundation
import Testing

@testable import MooringKit

@Suite(.timeLimit(.minutes(1))) struct SubprocessTests {
    /// A descriptor open for writing only: read(2) on it fails with EBADF,
    /// the one read failure a test can cause at will.
    private func writeOnly() throws -> FileHandle {
        try #require(FileHandle(forWritingAtPath: "/dev/null"))
    }

    @Test func aFailedReadIsAnErrorNotTheEnd() throws {
        let handle = try writeOnly()
        var buffer = [UInt8](repeating: 0, count: 16)
        #expect(throws: POSIXError(.EBADF)) { try Subprocess.readSome(handle, into: &buffer) }
        #expect(throws: POSIXError(.EBADF)) { try Subprocess.readAll(handle, limit: 16) }
        try handle.close()
    }

    @Test func stderrThatCannotBeReadSaysSo() throws {
        let handle = try writeOnly()
        // Described as the reads' error is, an `any Error`.
        let failure: any Error = POSIXError(.EBADF)
        #expect(Subprocess.collect(handle) == "(stderr could not be read: \(failure))")
        try handle.close()
    }
}
