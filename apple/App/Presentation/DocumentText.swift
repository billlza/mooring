// SPDX-License-Identifier: GPL-3.0-or-later

// How the console words why a one-shot command left no document (the
// Router screen's history, the Events screen's journals): the reason in
// the user's language, with the figures the failure names, then what
// `mooringctl` said in its own words.

import MooringKit
import SwiftUI

extension DocumentFailure {
    var text: String {
        switch self {
        case .ended(let end): end.text
        case .tooLong(let limit):
            String(localized: "mooringctl printed more than \(limit / 1_048_576) MiB, so the app stopped reading it.")
        case .unsupportedVersion(let found, let reads):
            String(localized: "mooringctl printed a document of version \(found); this build reads version \(reads).")
        case .unreadable(let why): String(localized: "What mooringctl printed could not be read: \(why)")
        }
    }
}
