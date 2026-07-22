package com.strike48.pickcrux.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.strike48.pick.shared.MarkdownBlock
import com.strike48.pick.shared.Span
import com.strike48.pick.shared.SpanStyle as MdSpanStyle

/**
 * Block-level markdown renderer driven by the SHARED Rust parser. Markdown is
 * parsed once in the crux core (pulldown-cmark) into `List<MarkdownBlock>`;
 * this composable walks those blocks/spans and renders each natively. No
 * parsing happens here — both native shells render from the one Rust impl.
 */
@Composable
fun MarkdownText(blocks: List<MarkdownBlock>, modifier: Modifier = Modifier) {
    Column(modifier = modifier.fillMaxWidth()) {
        blocks.forEach { block ->
            when (block) {
                is MarkdownBlock.CodeBlock -> CodeBlock(block.text)
                is MarkdownBlock.Heading -> Text(
                    text = inline(block.spans),
                    color = PickColors.Text,
                    fontWeight = FontWeight.Bold,
                    fontSize = when (block.level.toInt()) {
                        1 -> 22.sp
                        2 -> 19.sp
                        else -> 17.sp
                    },
                    modifier = Modifier.padding(top = 8.dp, bottom = 4.dp),
                )
                is MarkdownBlock.ListItem -> Text(
                    text = buildAnnotatedString {
                        append(if (block.ordered) "${block.number}. " else "•  ")
                        append(inline(block.spans))
                    },
                    color = PickColors.Text,
                    fontSize = 15.sp,
                    modifier = Modifier.padding(start = 8.dp, top = 2.dp, bottom = 2.dp),
                )
                is MarkdownBlock.Paragraph -> Text(
                    text = inline(block.spans),
                    color = PickColors.Text,
                    fontSize = 15.sp,
                    modifier = Modifier.padding(vertical = 3.dp),
                )
            }
        }
    }
}

@Composable
private fun CodeBlock(text: String) {
    Surface(
        color = PickColors.SubtleFill,
        shape = RoundedCornerShape(12.dp),
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
    ) {
        Text(
            text = text,
            fontFamily = FontFamily.Monospace,
            fontSize = 13.sp,
            color = PickColors.Text,
            modifier = Modifier.padding(PaddingValues(12.dp)),
        )
    }
}

/** Render pre-parsed inline spans, applying bold/italic/code styling per span. */
private fun inline(spans: List<Span>): AnnotatedString = buildAnnotatedString {
    spans.forEach { span ->
        when (span.style) {
            MdSpanStyle.BOLD -> withStyle(SpanStyle(fontWeight = FontWeight.Bold)) {
                append(span.text)
            }
            MdSpanStyle.ITALIC -> withStyle(SpanStyle(fontStyle = FontStyle.Italic)) {
                append(span.text)
            }
            MdSpanStyle.CODE -> withStyle(
                SpanStyle(fontFamily = FontFamily.Monospace, background = PickColors.SubtleFill),
            ) {
                append(span.text)
            }
            MdSpanStyle.PLAIN -> append(span.text)
        }
    }
}
