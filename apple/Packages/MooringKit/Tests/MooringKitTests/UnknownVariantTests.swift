// SPDX-License-Identifier: GPL-3.0-or-later

// Every enum the mirror reads by hand from its externally tagged form
// refuses a variant it does not name, in either form a variant takes (a
// bare string, or an object with the variant's name as its one key), as
// the Rust types refuse it: with the error `unknownVariant` makes, not a
// looser failure. A new variant on the Rust side therefore shows in the
// console as a line it cannot read, never as a value read wrongly. (The
// enums with raw values are read by Swift's own `RawRepresentable`
// decoding, which refuses a value no case has.)

import Foundation
import Testing

@testable import MooringKit

/// An enum the mirror reads by hand, and how to read one.
struct TaggedEnum: Sendable, CustomTestStringConvertible {
    let name: String
    let read: @Sendable (Data) throws -> Void

    init<T: Decodable & Sendable>(_ type: T.Type) {
        name = String(describing: type)
        read = { _ = try JSONDecoder().decode(T.self, from: $0) }
    }

    var testDescription: String { name }
}

/// The tag no enum has.
private let unknownTag = "no_such_variant"

/// A value whose reading makes the error `unknownVariant` makes for
/// `unknownTag`, so that the tests compare errors rather than spell the
/// error's text.
private struct UnknownVariantError: Decodable {
    let error: DecodingError

    init(from decoder: any Decoder) throws {
        error = decoder.unknownVariant(unknownTag)
    }
}

@Suite struct UnknownVariantTests {
    /// The enums with unit variants or variants of either form.
    static let eitherForm = [
        TaggedEnum(ExitState.self), TaggedEnum(DegradedReason.self), TaggedEnum(DownReason.self),
        TaggedEnum(Violation.self), TaggedEnum(ForeignNetworkFinding.self), TaggedEnum(AllowedNetwork.self),
        TaggedEnum(ProcessEnd.self), TaggedEnum(InChainOutcome.self), TaggedEnum(WatchError.self),
        TaggedEnum(EngineRun.self), TaggedEnum(NodeAgentState.self), TaggedEnum(EngineHost.self),
        TaggedEnum(AlertCondition.self), TaggedEnum(UplinkUse.self), TaggedEnum(Saturation.self),
        TaggedEnum(StopPolicy.self), TaggedEnum(Crossing.self), TaggedEnum(ForecastView.self),
        TaggedEnum(UsageView.self), TaggedEnum(SuspendReason.self), TaggedEnum(UserStatus.self),
        TaggedEnum(QuotaState.self), TaggedEnum(ExpiryState.self), TaggedEnum(RadioState.self),
        TaggedEnum(SampledRadio.self), TaggedEnum(RadioEventKind.self),
    ]

    /// The enums that are always objects (the console document, the router
    /// panel, a radio poll): a string is refused before any variant is
    /// looked at, as not an object.
    static let alwaysAnObject = [
        TaggedEnum(ConsoleStatus.self), TaggedEnum(RouterReading.self), TaggedEnum(RadioPoll.self),
    ]

    /// An unknown variant in the form of an object, its value an object or
    /// `null`.
    static let unknownObjects = ["{\"\(unknownTag)\": {}}", "{\"\(unknownTag)\": null}"]

    /// An unknown variant in the form of a string.
    static let unknownString = "\"\(unknownTag)\""

    @Test(arguments: Self.eitherForm + Self.alwaysAnObject, Self.unknownObjects)
    func anUnknownVariantObjectIsRefusedAsUnknown(_ type: TaggedEnum, _ json: String) throws {
        try expectRefusedAsUnknown(type, json)
    }

    @Test(arguments: Self.eitherForm)
    func anUnknownVariantStringIsRefusedAsUnknown(_ type: TaggedEnum) throws {
        try expectRefusedAsUnknown(type, Self.unknownString)
    }

    @Test(arguments: Self.alwaysAnObject)
    func aStringIsRefusedAsNotAnObject(_ type: TaggedEnum) {
        let error = #expect(throws: DecodingError.self) { try type.read(Data(Self.unknownString.utf8)) }
        guard case .typeMismatch? = error else {
            Issue.record("not refused as not an object: \(String(describing: error))")
            return
        }
    }

    /// The lists above name every enum of the mirror's sources that reads
    /// a tag by hand, so an enum added there is tested here too.
    @Test func theListsNameEveryEnumReadByHand() throws {
        let listed = Set((Self.eitherForm + Self.alwaysAnObject).map(\.name))
        #expect(listed.count == Self.eitherForm.count + Self.alwaysAnObject.count)
        #expect(try enumsReadByHand() == listed)
    }

    /// Requires reading `json` as `type` to fail with the error
    /// `unknownVariant` makes, at the top of the document.
    private func expectRefusedAsUnknown(_ type: TaggedEnum, _ json: String) throws {
        let expected = try JSONDecoder().decode(UnknownVariantError.self, from: Data("{}".utf8)).error
        guard case .dataCorrupted(let expectedContext) = expected else {
            Issue.record("unknownVariant made \(expected)")
            return
        }
        let error = #expect(throws: DecodingError.self) { try type.read(Data(json.utf8)) }
        guard case .dataCorrupted(let context)? = error else {
            Issue.record("not refused as unknown: \(String(describing: error))")
            return
        }
        #expect(context.debugDescription == expectedContext.debugDescription)
        #expect(context.codingPath.isEmpty)
        #expect(context.underlyingError == nil)
    }

    /// The enums of the mirror's sources that read a tag by hand: each
    /// enum whose own body calls `decoder.variant()`, `decoder.onlyKey()`
    /// or `decoder.unknownVariant(_:)`. A call anywhere else (in a struct,
    /// an extension, or a type nested in an enum) is recorded as an issue,
    /// so that no enum reading a tag escapes the lists above. The sources
    /// keep swift-format's layout, in which a declaration's closing brace
    /// sits alone at the declaration's own indentation; a file where that
    /// does not hold is recorded as an issue too.
    private func enumsReadByHand() throws -> Set<String> {
        let sources = Fixtures.root.appendingPathComponent("apple/Packages/MooringKit/Sources/MooringKit")
        let enumerator = try #require(FileManager.default.enumerator(at: sources, includingPropertiesForKeys: nil))
        let files = enumerator.compactMap { $0 as? URL }.filter { $0.pathExtension == "swift" }
        try #require(!files.isEmpty, "no sources at \(sources.path)")
        let calls = ["decoder.variant()", "decoder.onlyKey()", "decoder.unknownVariant("]
        var found: Set<String> = []
        for file in files {
            // The declarations a line is in, the innermost last.
            var open: [(declaration: TypeDeclaration, indentation: Substring)] = []
            let lines = try String(contentsOf: file, encoding: .utf8).split(
                separator: "\n", omittingEmptySubsequences: false)
            for (index, line) in lines.enumerated() {
                let indentation = line.prefix { $0 == " " }
                let text = line.dropFirst(indentation.count)
                if let innermost = open.last, indentation == innermost.indentation, text == "}" {
                    open.removeLast()
                } else if let declaration = TypeDeclaration(text) {
                    open.append((declaration, indentation))
                } else if !text.hasPrefix("//"), calls.contains(where: { text.contains($0) }) {
                    if case .enumeration(let name)? = open.last?.declaration {
                        found.insert(name)
                    } else {
                        Issue.record("\(file.lastPathComponent):\(index + 1) reads a tag outside an enum's own body")
                    }
                }
            }
            #expect(open.isEmpty, "\(file.lastPathComponent): a declaration's closing brace was not found")
        }
        return found
    }
}

/// A type declaration, read from its first line: an enum, with its name,
/// or another type.
private enum TypeDeclaration {
    case enumeration(String)
    case other

    private static let modifiers: Set<Substring> = [
        "public", "package", "internal", "fileprivate", "private", "open", "final", "indirect", "nonisolated",
    ]
    private static let keywords: Set<Substring> = ["enum", "struct", "class", "actor", "extension", "protocol"]

    /// The declaration `text` (a line without its indentation) begins, if
    /// it begins one whose body ends on a later line.
    init?(_ text: Substring) {
        var words = text.split(separator: " ")[...]
        while let word = words.first, word.hasPrefix("@") || Self.modifiers.contains(word) {
            words = words.dropFirst()
        }
        guard let keyword = words.first, Self.keywords.contains(keyword), let name = words.dropFirst().first,
            !text.hasSuffix("}")
        else {
            return nil
        }
        guard keyword == "enum" else {
            self = .other
            return
        }
        self = .enumeration(String(name.prefix { $0.isLetter || $0.isNumber || $0 == "_" }))
    }
}
