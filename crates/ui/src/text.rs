//! Shared text helpers for UI rendering.
//!
//! These run inside Dioxus `rsx!` render bodies, where a panic is caught by the
//! per-VirtualDom error boundary and blanks the pane (see issues #287/#288).
//! Anything here must therefore be panic-free on arbitrary backend/user data.

/// Truncate `text` to at most `max_chars` **characters** (not bytes), appending
/// an ellipsis (`...`) when truncation occurs.
///
/// Slicing a `&str` by a byte index (`&s[..n]`) panics if that index is not a
/// UTF-8 char boundary. Backend-supplied strings (AI-generated conversation
/// titles, tool arguments) routinely contain multi-byte characters (accents,
/// emoji, CJK, smart quotes), so any byte-index truncation on that data is a
/// latent render-panic. This helper counts characters instead, so it is safe
/// for every possible input.
///
/// The returned string is at most `max_chars + 3` characters long (the ellipsis
/// is appended, matching the previous byte-slice call sites' behavior).
///
/// ```
/// use pentest_ui::text::truncate_chars;
/// assert_eq!(truncate_chars("hello", 10), "hello");
/// assert_eq!(truncate_chars("hello world", 5), "hello...");
/// // A multi-byte char straddling the cutoff does not panic:
/// assert_eq!(truncate_chars("aaaaé", 4), "aaaa...");
/// ```
pub fn truncate_chars(text: &str, max_chars: usize) -> String {
    // Fast path: count without allocating. `chars().count()` walks the string
    // once; for the short titles/labels these call sites handle this is cheap.
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let truncated: String = text.chars().take(max_chars).collect();
    format!("{truncated}...")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_input_unchanged_when_within_limit() {
        assert_eq!(truncate_chars("hello", 10), "hello");
        assert_eq!(truncate_chars("", 5), "");
    }

    #[test]
    fn returns_input_unchanged_at_exact_limit() {
        assert_eq!(truncate_chars("hello", 5), "hello");
    }

    #[test]
    fn appends_ellipsis_when_over_limit() {
        assert_eq!(truncate_chars("hello world", 5), "hello...");
    }

    #[test]
    fn counts_characters_not_bytes() {
        // Five 'é' chars = 10 bytes but 5 chars; within a 5-char limit.
        assert_eq!(truncate_chars("ééééé", 5), "ééééé");
    }

    #[test]
    fn does_not_panic_when_multibyte_char_straddles_byte_cutoff() {
        // This is the exact shape from issue #287: a 2-byte 'é' straddles the
        // byte-25 cutoff of the old `&title[..25]` slice. Byte-slicing panics
        // with "byte index 25 is not a char boundary"; truncate_chars must not.
        let title = format!("{}\u{e9}review of scope", "a".repeat(24));
        assert!(title.len() > 28, "precondition: title exceeds byte guard");

        // Old code: `&title[..25]` — would panic here. New code must succeed.
        let out = truncate_chars(&title, 25);

        // 25 chars kept + ellipsis. The 25th char is the 'é'.
        assert_eq!(out.chars().count(), 25 + "...".chars().count());
        assert!(out.ends_with("..."));
        assert!(out.starts_with(&"a".repeat(24)));
        assert!(out.contains('\u{e9}'));
    }

    #[test]
    fn handles_emoji_and_cjk_at_boundary() {
        // Emoji (4-byte) and CJK (3-byte) straddling the cutoff must not panic.
        let emoji = format!("{}\u{1f600}tail", "x".repeat(24)); // grinning face
        let cjk = format!("{}\u{4e2d}\u{6587}tail", "y".repeat(24)); // 中文
        assert_eq!(truncate_chars(&emoji, 25).chars().count(), 28);
        assert_eq!(truncate_chars(&cjk, 25).chars().count(), 28);
    }
}
