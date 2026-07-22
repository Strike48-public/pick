package com.strike48.pickcrux.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
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

/**
 * Hand-rolled, dependency-free markdown renderer. Supports headings (#..###),
 * unordered/ordered lists, fenced code blocks (```), inline **bold**, *italic*,
 * and `code`. Deliberately lightweight — no external markdown library.
 */
@Composable
fun MarkdownText(markdown: String, modifier: Modifier = Modifier) {
    val blocks = remember(markdown) { parseBlocks(markdown) }
    Column(modifier = modifier.fillMaxWidth()) {
        blocks.forEach { block ->
            when (block) {
                is MdBlock.Code -> CodeBlock(block.text)
                is MdBlock.Heading -> Text(
                    text = inlineMarkdown(block.text),
                    color = PickColors.Text,
                    fontWeight = FontWeight.Bold,
                    fontSize = when (block.level) {
                        1 -> 22.sp
                        2 -> 19.sp
                        else -> 17.sp
                    },
                    modifier = Modifier.padding(top = 8.dp, bottom = 4.dp),
                )
                is MdBlock.ListItem -> Text(
                    text = buildAnnotatedString {
                        append(if (block.ordered) "${block.marker}. " else "•  ")
                        append(inlineMarkdown(block.text))
                    },
                    color = PickColors.Text,
                    fontSize = 15.sp,
                    modifier = Modifier.padding(start = 8.dp, top = 2.dp, bottom = 2.dp),
                )
                is MdBlock.Paragraph -> if (block.text.isNotBlank()) {
                    Text(
                        text = inlineMarkdown(block.text),
                        color = PickColors.Text,
                        fontSize = 15.sp,
                        modifier = Modifier.padding(vertical = 3.dp),
                    )
                }
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

private sealed interface MdBlock {
    data class Heading(val level: Int, val text: String) : MdBlock
    data class Paragraph(val text: String) : MdBlock
    data class ListItem(val text: String, val ordered: Boolean, val marker: String) : MdBlock
    data class Code(val text: String) : MdBlock
}

private fun parseBlocks(markdown: String): List<MdBlock> {
    val out = mutableListOf<MdBlock>()
    val lines = markdown.replace("\r\n", "\n").split("\n")
    var i = 0
    val paragraph = StringBuilder()

    fun flushParagraph() {
        if (paragraph.isNotBlank()) out.add(MdBlock.Paragraph(paragraph.toString().trim()))
        paragraph.setLength(0)
    }

    while (i < lines.size) {
        val line = lines[i]
        val trimmed = line.trimStart()
        when {
            trimmed.startsWith("```") -> {
                flushParagraph()
                val code = StringBuilder()
                i++
                while (i < lines.size && !lines[i].trimStart().startsWith("```")) {
                    code.appendLine(lines[i])
                    i++
                }
                out.add(MdBlock.Code(code.toString().trimEnd('\n')))
            }
            trimmed.startsWith("#") -> {
                flushParagraph()
                val level = trimmed.takeWhile { it == '#' }.length.coerceIn(1, 3)
                out.add(MdBlock.Heading(level, trimmed.drop(level).trim()))
            }
            trimmed.startsWith("- ") || trimmed.startsWith("* ") -> {
                flushParagraph()
                out.add(MdBlock.ListItem(trimmed.drop(2).trim(), ordered = false, marker = ""))
            }
            trimmed.matches(Regex("^\\d+\\.\\s.*")) -> {
                flushParagraph()
                val marker = trimmed.takeWhile { it.isDigit() }
                out.add(MdBlock.ListItem(trimmed.substringAfter(". ").trim(), ordered = true, marker = marker))
            }
            trimmed.isBlank() -> flushParagraph()
            else -> {
                if (paragraph.isNotEmpty()) paragraph.append(' ')
                paragraph.append(trimmed)
            }
        }
        i++
    }
    flushParagraph()
    return out
}

/** Inline formatting: **bold**, *italic*, `code`. */
private fun inlineMarkdown(text: String): AnnotatedString = buildAnnotatedString {
    var i = 0
    while (i < text.length) {
        when {
            text.startsWith("**", i) -> {
                val end = text.indexOf("**", i + 2)
                if (end != -1) {
                    withStyle(SpanStyle(fontWeight = FontWeight.Bold)) {
                        append(text.substring(i + 2, end))
                    }
                    i = end + 2
                } else { append(text.substring(i)); i = text.length }
            }
            text[i] == '*' -> {
                val end = text.indexOf('*', i + 1)
                if (end != -1) {
                    withStyle(SpanStyle(fontStyle = FontStyle.Italic)) {
                        append(text.substring(i + 1, end))
                    }
                    i = end + 1
                } else { append(text[i]); i++ }
            }
            text[i] == '`' -> {
                val end = text.indexOf('`', i + 1)
                if (end != -1) {
                    withStyle(SpanStyle(fontFamily = FontFamily.Monospace, background = PickColors.SubtleFill)) {
                        append(text.substring(i + 1, end))
                    }
                    i = end + 1
                } else { append(text[i]); i++ }
            }
            else -> { append(text[i]); i++ }
        }
    }
}
