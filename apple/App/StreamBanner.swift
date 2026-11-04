// SPDX-License-Identifier: GPL-3.0-or-later

import MooringKit
import SwiftUI

/// Where the stream stands, above every screen: live with the time the
/// daemon made the document shown, or why it is not live.
struct StreamBanner: View {
    let model: ConsoleModel

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: symbol)
                .foregroundStyle(tint)
            VStack(alignment: .leading, spacing: 2) {
                Text(headline)
                    .font(.callout.weight(.semibold))
                // Only a retry countdown changes with wall-clock time.
                // Live status is driven by the model, not a per-second
                // redraw of the whole banner in every console window.
                if case .ended = model.state {
                    TimelineView(.periodic(from: .now, by: 1)) { context in
                        detailText(now: context.date)
                    }
                } else {
                    detailText(now: .now)
                }
            }
            Spacer()
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
        .background(tint.opacity(0.08))
    }

    @ViewBuilder private func detailText(now: Date) -> some View {
        if let detail = detail(now: now) {
            Text(detail)
                .font(.caption)
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
        }
    }

    private var symbol: String {
        switch model.state {
        case .live: "dot.radiowaves.left.and.right"
        case .connecting, .stopped: "hourglass"
        case .refusing, .ended, .retrying, .noCommand: "exclamationmark.triangle.fill"
        }
    }

    private var tint: Color {
        switch model.state {
        case .live: .green
        case .connecting, .stopped: .secondary
        case .refusing, .ended, .retrying, .noCommand: .orange
        }
    }

    private var headline: LocalizedStringKey {
        switch model.state {
        case .live: "Live from the Mooring daemon"
        case .connecting: "Waiting for the Mooring daemon…"
        case .refusing: "Not live: the latest status cannot be shown"
        case .ended, .retrying: "Not live: mooringctl stopped"
        case .stopped: "Not reading the daemon's status"
        case .noCommand: "This app carries no mooringctl"
        }
    }

    private func detail(now: Date) -> String? {
        var parts: [String] = []
        if let at = model.status?.at {
            parts.append(String(localized: "Status from \(at.date.formatted(date: .omitted, time: .standard))"))
        }
        switch model.state {
        case .ended(let end, let retryAt):
            let seconds = max(0, Int(retryAt.timeIntervalSince(now).rounded(.up)))
            parts.append(end.text)
            parts.append(String(localized: "Retrying in \(seconds) s."))
        case .retrying(let end):
            parts.append(end.text)
            parts.append(String(localized: "Retrying…"))
        case .refusing(let refusal):
            parts.append(refusal.text)
        case .noCommand(let path):
            parts.append(String(localized: "Expected at \(path)."))
        case .connecting where model.status == nil:
            parts.append(
                String(
                    localized:
                        "The daemon reports after its first poll of the M7, which waits while macOS asks you to allow keychain or local network access."
                ))
        case .live, .connecting, .stopped:
            break
        }
        return parts.isEmpty ? nil : parts.joined(separator: "  ·  ")
    }
}

extension StreamEnd {
    /// How the command ended, in the user's language, then what it said
    /// (`mooringctl`'s own words).
    var text: String {
        let how =
            switch reason {
            case .exited(let code): String(localized: "mooringctl exited with code \(code).")
            case .signalled(let signal): String(localized: "mooringctl was ended by signal \(signal).")
            case .notStarted(let why): String(localized: "mooringctl could not be started: \(why)")
            }
        return message.isEmpty ? how : "\(how) \(message)"
    }
}

extension LineRefusal {
    /// Why the latest line is not shown, in the user's language.
    var text: String {
        switch self {
        case .unsupportedVersion(let version):
            String(localized: "The daemon's document is version \(version); this build reads version 1.")
        case .unreadable(let why):
            String(localized: "A line from mooringctl could not be read: \(why)")
        case .tooLong:
            String(localized: "A line from mooringctl was longer than 1 MiB, so the app stopped reading it.")
        }
    }
}
