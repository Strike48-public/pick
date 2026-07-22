//! Shared markdown parser. Parses agent chat messages and report bodies into
//! structured, render-ready blocks so both native shells (iOS/Android) render
//! from ONE Rust implementation (pulldown-cmark) instead of hand-rolled
//! per-shell parsers. The block/span types are Facet-typegen-compatible and
//! surface in the ViewModel; a shell walks the blocks and renders each natively.

use facet::Facet;
use serde::{Deserialize, Serialize};

/// A top-level rendered block. Nested lists are flattened to top-level items.
#[derive(Facet, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[repr(C)]
pub enum MarkdownBlock {
    Heading { level: u8, spans: Vec<Span> },
    Paragraph { spans: Vec<Span> },
    /// A list item. `number` is 0 for unordered items.
    ListItem {
        ordered: bool,
        number: u32,
        spans: Vec<Span>,
    },
    /// A fenced/indented code block. Its text is verbatim, never styled inline.
    CodeBlock { text: String },
}

/// The inline style applied to a span of text. Bold+italic collapses to Bold.
#[derive(Facet, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[repr(C)]
pub enum SpanStyle {
    Plain,
    Bold,
    Italic,
    Code,
}

/// A run of text with a single inline style.
#[derive(Facet, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[repr(C)]
pub struct Span {
    pub text: String,
    pub style: SpanStyle,
}

/// Parse markdown into render-ready blocks. Pure and total (never panics);
/// unknown constructs degrade to their text content as Plain spans.
pub fn parse_markdown(src: &str) -> Vec<MarkdownBlock> {
    use pulldown_cmark::{Event, HeadingLevel, Options, Parser, Tag, TagEnd};

    let options =
        Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH | Options::ENABLE_TASKLISTS;
    let parser = Parser::new_ext(src, options);

    let mut blocks: Vec<MarkdownBlock> = Vec::new();

    // Current open block being accumulated.
    enum Open {
        None,
        Heading(u8),
        Paragraph,
        Item { ordered: bool, number: u32 },
        Code,
    }
    let mut open = Open::None;
    let mut spans: Vec<Span> = Vec::new();
    let mut code_text = String::new();

    // Inline style stack; the top wins, with Bold preferred over Italic.
    let mut bold_depth: u32 = 0;
    let mut italic_depth: u32 = 0;

    // Stack of enclosing lists: (ordered, next_number).
    let mut list_stack: Vec<(bool, u32)> = Vec::new();

    fn current_style(bold: u32, italic: u32) -> SpanStyle {
        if bold > 0 {
            SpanStyle::Bold
        } else if italic > 0 {
            SpanStyle::Italic
        } else {
            SpanStyle::Plain
        }
    }

    // Append text with the given style, merging into the last span if same style.
    fn push_span(spans: &mut Vec<Span>, text: &str, style: SpanStyle) {
        if text.is_empty() {
            return;
        }
        if let Some(last) = spans.last_mut() {
            if last.style == style {
                last.text.push_str(text);
                return;
            }
        }
        spans.push(Span {
            text: text.to_string(),
            style,
        });
    }

    let level_num = |lvl: HeadingLevel| -> u8 {
        match lvl {
            HeadingLevel::H1 => 1,
            HeadingLevel::H2 => 2,
            HeadingLevel::H3 => 3,
            HeadingLevel::H4 => 4,
            HeadingLevel::H5 => 5,
            HeadingLevel::H6 => 6,
        }
    };

    for event in parser {
        match event {
            Event::Start(Tag::Heading { level, .. }) => {
                spans = Vec::new();
                open = Open::Heading(level_num(level));
            }
            Event::End(TagEnd::Heading(_)) => {
                if let Open::Heading(level) = open {
                    blocks.push(MarkdownBlock::Heading {
                        level,
                        spans: std::mem::take(&mut spans),
                    });
                }
                open = Open::None;
            }
            Event::Start(Tag::Paragraph) => {
                spans = Vec::new();
                open = Open::Paragraph;
            }
            Event::End(TagEnd::Paragraph) => {
                if let Open::Paragraph = open {
                    blocks.push(MarkdownBlock::Paragraph {
                        spans: std::mem::take(&mut spans),
                    });
                }
                open = Open::None;
            }
            Event::Start(Tag::List(start)) => {
                let ordered = start.is_some();
                let first = start.map(|s| s as u32).unwrap_or(0);
                list_stack.push((ordered, first));
            }
            Event::End(TagEnd::List(_)) => {
                list_stack.pop();
            }
            Event::Start(Tag::Item) => {
                let (ordered, number) = match list_stack.last_mut() {
                    Some((ordered, next)) => {
                        let n = if *ordered { *next } else { 0 };
                        if *ordered {
                            *next += 1;
                        }
                        (*ordered, n)
                    }
                    None => (false, 0),
                };
                spans = Vec::new();
                open = Open::Item { ordered, number };
            }
            Event::End(TagEnd::Item) => {
                if let Open::Item { ordered, number } = open {
                    blocks.push(MarkdownBlock::ListItem {
                        ordered,
                        number,
                        spans: std::mem::take(&mut spans),
                    });
                }
                open = Open::None;
            }
            Event::Start(Tag::CodeBlock(_)) => {
                code_text = String::new();
                open = Open::Code;
            }
            Event::End(TagEnd::CodeBlock) => {
                // Trim a single trailing newline that pulldown-cmark emits.
                let mut text = std::mem::take(&mut code_text);
                if text.ends_with('\n') {
                    text.pop();
                }
                blocks.push(MarkdownBlock::CodeBlock { text });
                open = Open::None;
            }
            Event::Start(Tag::Strong) => bold_depth += 1,
            Event::End(TagEnd::Strong) => bold_depth = bold_depth.saturating_sub(1),
            Event::Start(Tag::Emphasis) => italic_depth += 1,
            Event::End(TagEnd::Emphasis) => italic_depth = italic_depth.saturating_sub(1),
            Event::Text(text) => {
                if let Open::Code = open {
                    code_text.push_str(&text);
                } else {
                    let style = current_style(bold_depth, italic_depth);
                    push_span(&mut spans, &text, style);
                }
            }
            Event::Code(text) => {
                if let Open::Code = open {
                    code_text.push_str(&text);
                } else {
                    push_span(&mut spans, &text, SpanStyle::Code);
                }
            }
            Event::SoftBreak => {
                if let Open::Code = open {
                    code_text.push('\n');
                } else {
                    let style = current_style(bold_depth, italic_depth);
                    push_span(&mut spans, " ", style);
                }
            }
            Event::HardBreak => {
                if let Open::Code = open {
                    code_text.push('\n');
                } else {
                    let style = current_style(bold_depth, italic_depth);
                    push_span(&mut spans, "\n", style);
                }
            }
            // Unknown/other tags and events degrade gracefully: any text they
            // contain is captured by the Event::Text arm above as Plain spans.
            _ => {}
        }
    }

    blocks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heading_becomes_heading_with_level() {
        let blocks = parse_markdown("## Title");
        assert_eq!(blocks.len(), 1);
        match &blocks[0] {
            MarkdownBlock::Heading { level, spans } => {
                assert_eq!(*level, 2);
                assert_eq!(spans.len(), 1);
                assert_eq!(spans[0].text, "Title");
                assert_eq!(spans[0].style, SpanStyle::Plain);
            }
            other => panic!("expected heading, got {other:?}"),
        }
    }

    #[test]
    fn bold_becomes_bold_span() {
        let blocks = parse_markdown("**bold**");
        match &blocks[0] {
            MarkdownBlock::Paragraph { spans } => {
                assert_eq!(spans.len(), 1);
                assert_eq!(spans[0].text, "bold");
                assert_eq!(spans[0].style, SpanStyle::Bold);
            }
            other => panic!("expected paragraph, got {other:?}"),
        }
    }

    #[test]
    fn fenced_code_block_has_no_inline_styling() {
        let src = "```\nlet **x** = `y`\n```";
        let blocks = parse_markdown(src);
        assert_eq!(blocks.len(), 1);
        match &blocks[0] {
            MarkdownBlock::CodeBlock { text } => {
                assert_eq!(text, "let **x** = `y`");
            }
            other => panic!("expected code block, got {other:?}"),
        }
    }

    #[test]
    fn unordered_and_ordered_list_items() {
        let blocks = parse_markdown("- a");
        match &blocks[0] {
            MarkdownBlock::ListItem {
                ordered,
                number,
                spans,
            } => {
                assert!(!*ordered);
                assert_eq!(*number, 0);
                assert_eq!(spans[0].text, "a");
            }
            other => panic!("expected list item, got {other:?}"),
        }

        let blocks = parse_markdown("1. b");
        match &blocks[0] {
            MarkdownBlock::ListItem {
                ordered,
                number,
                spans,
            } => {
                assert!(*ordered);
                assert_eq!(*number, 1);
                assert_eq!(spans[0].text, "b");
            }
            other => panic!("expected list item, got {other:?}"),
        }
    }

    #[test]
    fn ordered_list_increments_numbers() {
        let blocks = parse_markdown("1. one\n2. two\n3. three");
        let numbers: Vec<u32> = blocks
            .iter()
            .filter_map(|b| match b {
                MarkdownBlock::ListItem { number, .. } => Some(*number),
                _ => None,
            })
            .collect();
        assert_eq!(numbers, vec![1, 2, 3]);
    }

    #[test]
    fn ordered_list_respects_start() {
        let blocks = parse_markdown("5. five\n6. six");
        let numbers: Vec<u32> = blocks
            .iter()
            .filter_map(|b| match b {
                MarkdownBlock::ListItem { number, .. } => Some(*number),
                _ => None,
            })
            .collect();
        assert_eq!(numbers, vec![5, 6]);
    }

    #[test]
    fn mixed_inline_styles_in_order() {
        let blocks = parse_markdown("**b** and *i* and `c`");
        match &blocks[0] {
            MarkdownBlock::Paragraph { spans } => {
                assert_eq!(spans[0].text, "b");
                assert_eq!(spans[0].style, SpanStyle::Bold);
                // " and " plain
                assert_eq!(spans[1].style, SpanStyle::Plain);
                assert_eq!(spans[1].text, " and ");
                assert_eq!(spans[2].text, "i");
                assert_eq!(spans[2].style, SpanStyle::Italic);
                assert_eq!(spans[3].style, SpanStyle::Plain);
                assert_eq!(spans[3].text, " and ");
                assert_eq!(spans[4].text, "c");
                assert_eq!(spans[4].style, SpanStyle::Code);
            }
            other => panic!("expected paragraph, got {other:?}"),
        }
    }

    #[test]
    fn nested_bold_italic_prefers_bold() {
        let blocks = parse_markdown("***both***");
        match &blocks[0] {
            MarkdownBlock::Paragraph { spans } => {
                assert_eq!(spans[0].text, "both");
                assert_eq!(spans[0].style, SpanStyle::Bold);
            }
            other => panic!("expected paragraph, got {other:?}"),
        }
    }

    #[test]
    fn soft_break_becomes_space() {
        let blocks = parse_markdown("line one\nline two");
        match &blocks[0] {
            MarkdownBlock::Paragraph { spans } => {
                let text: String = spans.iter().map(|s| s.text.as_str()).collect();
                assert_eq!(text, "line one line two");
            }
            other => panic!("expected paragraph, got {other:?}"),
        }
    }

    #[test]
    fn empty_input_yields_no_blocks() {
        assert!(parse_markdown("").is_empty());
    }
}
