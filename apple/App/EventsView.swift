// SPDX-License-Identifier: GPL-3.0-or-later

// The events screen (design §15.7): the Mac's event journal and the
// daemon's copies of the nodes' journals over the CLI's default range,
// the last seven UTC days, as `mooringctl events --json` prints them; run
// when the screen first shows and on Reload. The entries are listed by
// the day of their time in the user's calendar, newest first. The open
// alerts stay on the overview.

import MooringKit
import SwiftUI

struct EventsView: View {
    let events: DocumentModel<EventsDocument>

    var body: some View {
        List {
            Section {
                switch events.state {
                case .idle, .loading:
                    HStack(spacing: 8) {
                        ProgressView()
                            .controlSize(.small)
                        Text("Loading the journals…")
                            .foregroundStyle(.secondary)
                    }
                case .noCommand:
                    Text("This app carries no mooringctl")
                        .foregroundStyle(.secondary)
                case .failed(let failure, let at):
                    Text(failure.text)
                        .foregroundStyle(.orange)
                        .textSelection(.enabled)
                    LabeledContent("Read at", value: at.formatted(date: .omitted, time: .standard))
                case .loaded(let document, let at):
                    JournalsSummary(document: document, at: at)
                }
                // A row rather than the section's footer, which a list
                // cuts to one line.
                Text(
                    "The daemon journals the Mac's events as its status shows them, and reads each node's journal every 5 minutes; a node's events carry the node's clock. The journals keep the newest 393 days (`mooringctl events --since <date> --until <date>` prints them)."
                )
                .font(.caption)
                .foregroundStyle(.secondary)
            } header: {
                HStack {
                    Text("Journals")
                    Spacer()
                    Button("Reload") {
                        events.reload()
                    }
                    .disabled(events.state == .loading)
                }
            }
            if case .loaded(let document, _) = events.state {
                ForEach(document.days(in: .current), id: \.start) { day in
                    Section(day.start.formatted(date: .complete, time: .omitted)) {
                        ForEach(Array(day.entries.enumerated()), id: \.offset) { _, entry in
                            EventRow(entry: entry)
                        }
                    }
                }
            }
        }
        .task {
            if case .idle = events.state {
                events.reload()
            }
        }
    }
}

/// The days read, the entries listed, what the bound left out and the
/// files that ended in an incomplete line.
struct JournalsSummary: View {
    let document: EventsDocument
    let at: Date

    var body: some View {
        LabeledContent("Days (UTC)", value: "\(document.since.display) – \(document.until.display)")
        LabeledContent("Entries", value: "\(document.entries.count)")
        LabeledContent("Read at", value: at.formatted(date: .omitted, time: .standard))
        if document.entries.isEmpty {
            Text("No events in these days.")
                .foregroundStyle(.secondary)
        }
        if document.omitted > 0 {
            Text(
                "Older entries left out: \(document.omitted). `mooringctl events --since <date> --until <date>` reads fewer days at a time."
            )
            .foregroundStyle(.secondary)
        }
        ForEach(document.incompleteDays, id: \.self) { day in
            Group {
                if let node = day.node {
                    Text(
                        "\(day.day.display), \(node.text)'s copy: the last line is incomplete; the daemon may be writing it, or stopped while writing it."
                    )
                } else {
                    Text(
                        "\(day.day.display), the Mac's journal: the last line is incomplete; the daemon may be writing it, or stopped while writing it."
                    )
                }
            }
            .font(.caption)
            .foregroundStyle(.secondary)
        }
    }
}

/// An entry: its time in the user's time zone, whose journal it is from,
/// and what happened.
struct EventRow: View {
    let entry: JournalEntry

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Text(entry.at.date.formatted(date: .omitted, time: .standard))
                .monospacedDigit()
                .foregroundStyle(.secondary)
            // Wide enough for the longest node id, 12 characters.
            source
                .lineLimit(1)
                .frame(width: 84, alignment: .leading)
                .foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 2) {
                switch entry {
                case .mac(let event):
                    HStack(alignment: .firstTextBaseline, spacing: 6) {
                        if case .exit(let phase) = event.kind {
                            Image(systemName: phase.symbol)
                                .foregroundStyle(phase.tint)
                        }
                        Text(event.kind.text)
                    }
                    if let details = event.kind.details {
                        Text(details)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                case .node(_, let line):
                    Text(line.entry.text)
                }
            }
            .textSelection(.enabled)
        }
    }

    @ViewBuilder private var source: some View {
        switch entry {
        case .mac: Text(verbatim: "Mac")
        case .node(let node, _): Text(verbatim: node.text)
        }
    }
}
