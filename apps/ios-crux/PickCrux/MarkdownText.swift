import SwiftUI
import PickShared

/// Block-level Markdown renderer driven by the SHARED Rust parser. Markdown is
/// parsed once in the crux core (pulldown-cmark) into `[MarkdownBlock]`; this
/// view walks those blocks/spans and renders each natively. No parsing happens
/// here — both native shells render from the one Rust implementation.
struct MarkdownText: View {
    let blocks: [MarkdownBlock]

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            ForEach(Array(blocks.enumerated()), id: \.offset) { _, block in
                switch block {
                case let .heading(level, spans):
                    text(spans)
                        .font(.system(size: level == 1 ? 22 : level == 2 ? 19 : 17, weight: .bold))
                        .foregroundStyle(Theme.text)
                        .padding(.top, 8)
                        .padding(.bottom, 2)
                case let .listItem(ordered, number, spans):
                    HStack(alignment: .top, spacing: 6) {
                        Text(ordered ? "\(number)." : "\u{2022}")
                            .foregroundStyle(Theme.text)
                            .font(.system(size: 15))
                        text(spans)
                            .foregroundStyle(Theme.text)
                            .font(.system(size: 15))
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .padding(.leading, 8)
                case let .codeBlock(code, _):
                    Text(code)
                        .font(.system(size: 13, design: .monospaced))
                        .foregroundStyle(Theme.text)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(10)
                        .background(Theme.subtleFill, in: RoundedCornerShape())
                case let .mermaid(code):
                    MermaidView(code: code)
                        .frame(maxWidth: .infinity, alignment: .leading)
                case let .paragraph(spans):
                    text(spans)
                        .foregroundStyle(Theme.text)
                        .font(.system(size: 15))
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    /// Build a single `Text` by concatenating styled span runs.
    private func text(_ spans: [Span]) -> Text {
        spans.reduce(Text("")) { acc, span in acc + styled(span) }
    }

    private func styled(_ span: Span) -> Text {
        let base = Text(span.text)
        switch span.style {
        case .bold:
            return base.bold()
        case .italic:
            return base.italic()
        case .code:
            return base.font(.system(size: 15, design: .monospaced))
        case .plain:
            return base
        }
    }
}

/// A rounded rectangle shape helper (12pt) matching the sage card radius.
private struct RoundedCornerShape: Shape {
    func path(in rect: CGRect) -> Path {
        Path(roundedRect: rect, cornerRadius: 12)
    }
}
