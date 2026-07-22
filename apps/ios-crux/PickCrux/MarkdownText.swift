import SwiftUI

/// Dependency-free block-level Markdown renderer, mirroring the Android shell's
/// `MarkdownText`. SwiftUI's `AttributedString(markdown:)` only does *inline*
/// formatting and collapses block structure/newlines, so headings, lists, and
/// paragraphs render as one run-on line. This splits the source into blocks
/// (headings `#..###`, fenced code ```` ``` ````, `-`/`*`/`1.` list items,
/// paragraphs) and renders each, applying inline **bold**/*italic*/`code` via
/// AttributedString within a block.
struct MarkdownText: View {
    let markdown: String

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            ForEach(Array(Self.parse(markdown).enumerated()), id: \.offset) { _, block in
                switch block {
                case let .heading(level, text):
                    Text(inline(text))
                        .font(.system(size: level == 1 ? 22 : level == 2 ? 19 : 17, weight: .bold))
                        .foregroundStyle(Theme.text)
                        .padding(.top, 8)
                        .padding(.bottom, 2)
                case let .listItem(ordered, marker, text):
                    HStack(alignment: .top, spacing: 6) {
                        Text(ordered ? "\(marker)." : "•")
                            .foregroundStyle(Theme.text)
                            .font(.system(size: 15))
                        Text(inline(text))
                            .foregroundStyle(Theme.text)
                            .font(.system(size: 15))
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .padding(.leading, 8)
                case let .code(text):
                    Text(text)
                        .font(.system(size: 13, design: .monospaced))
                        .foregroundStyle(Theme.text)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(10)
                        .background(Theme.subtleFill, in: RoundedCornerShape())
                case let .paragraph(text):
                    Text(inline(text))
                        .foregroundStyle(Theme.text)
                        .font(.system(size: 15))
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    /// Inline formatting within a single block via AttributedString. Newlines
    /// never appear here (blocks are split first), so inline parsing is safe.
    private func inline(_ raw: String) -> AttributedString {
        (try? AttributedString(markdown: raw, options: .init(interpretedSyntax: .inlineOnly)))
            ?? AttributedString(raw)
    }

    // MARK: - Block parsing

    enum Block {
        case heading(level: Int, text: String)
        case listItem(ordered: Bool, marker: Int, text: String)
        case code(text: String)
        case paragraph(text: String)
    }

    static func parse(_ md: String) -> [Block] {
        var blocks: [Block] = []
        var paragraph: [String] = []
        var inCode = false
        var code: [String] = []

        func flushParagraph() {
            let joined = paragraph.joined(separator: " ").trimmingCharacters(in: .whitespaces)
            if !joined.isEmpty { blocks.append(.paragraph(text: joined)) }
            paragraph.removeAll()
        }

        for rawLine in md.components(separatedBy: "\n") {
            let line = rawLine

            if line.trimmingCharacters(in: .whitespaces).hasPrefix("```") {
                if inCode {
                    blocks.append(.code(text: code.joined(separator: "\n")))
                    code.removeAll()
                    inCode = false
                } else {
                    flushParagraph()
                    inCode = true
                }
                continue
            }
            if inCode {
                code.append(line)
                continue
            }

            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty {
                flushParagraph()
                continue
            }

            // Headings: #, ##, ###
            if let h = headingLevel(trimmed) {
                flushParagraph()
                let text = String(trimmed.drop(while: { $0 == "#" })).trimmingCharacters(in: .whitespaces)
                blocks.append(.heading(level: h, text: text))
                continue
            }

            // Unordered list: -, *, +
            if let first = trimmed.first, "-*+".contains(first),
               trimmed.count > 1, trimmed[trimmed.index(trimmed.startIndex, offsetBy: 1)] == " " {
                flushParagraph()
                let text = String(trimmed.dropFirst(2))
                blocks.append(.listItem(ordered: false, marker: 0, text: text))
                continue
            }

            // Ordered list: "1. ", "2. " ...
            if let (marker, rest) = orderedItem(trimmed) {
                flushParagraph()
                blocks.append(.listItem(ordered: true, marker: marker, text: rest))
                continue
            }

            paragraph.append(trimmed)
        }
        if inCode && !code.isEmpty { blocks.append(.code(text: code.joined(separator: "\n"))) }
        flushParagraph()
        return blocks
    }

    private static func headingLevel(_ s: String) -> Int? {
        var n = 0
        for c in s { if c == "#" { n += 1 } else { break } }
        guard (1...6).contains(n) else { return nil }
        // Must be followed by a space to be a heading.
        let idx = s.index(s.startIndex, offsetBy: n)
        guard idx < s.endIndex, s[idx] == " " else { return nil }
        return min(n, 3)
    }

    private static func orderedItem(_ s: String) -> (Int, String)? {
        let digits = s.prefix(while: { $0.isNumber })
        guard !digits.isEmpty, let n = Int(digits) else { return nil }
        let after = s[s.index(s.startIndex, offsetBy: digits.count)...]
        guard after.hasPrefix(". ") else { return nil }
        return (n, String(after.dropFirst(2)))
    }
}

/// A rounded rectangle shape helper (16pt) matching the sage card radius.
private struct RoundedCornerShape: Shape {
    func path(in rect: CGRect) -> Path {
        Path(roundedRect: rect, cornerRadius: 12)
    }
}
