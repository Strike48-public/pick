//! Shared validation helpers for the Active Directory attack tools.
//!
//! These keep the four AD wrappers DRY: a single metacharacter guard (copied
//! from `zap::validate_url`'s check) and a conservative path/flag allowlist used
//! for free-form positional values such as wordlist paths and `extra_args`.

use pentest_core::error::Result;

/// Reject shell metacharacters defensively even though args are passed as an
/// argv vector (never a shell string). Mirrors `zap::validate_url` and
/// `metasploit::reject_metacharacters`.
///
/// Passwords may legitimately contain symbols, so callers validating a password
/// run this guard (which blocks shell-injection metacharacters) but NOT
/// [`pentest_core::validation::validate_target`] (which would reject normal
/// password punctuation). This is the documented tradeoff: we accept arbitrary
/// password symbols while still blocking the characters that could break out of
/// the argv boundary if the value were ever interpolated into a shell.
pub fn reject_metacharacters(value: &str, field: &str) -> Result<()> {
    if value.chars().any(|c| {
        matches!(
            c,
            ';' | '&' | '|' | '`' | '$' | '<' | '>' | '\n' | '\r' | '\\' | '"' | '\''
        )
    }) {
        return Err(pentest_core::error::Error::InvalidParams(format!(
            "{field} contains invalid characters"
        )));
    }
    Ok(())
}

/// Conservative allowlist for free-form flag/value tokens passed straight
/// through to a tool (e.g. Certipy `extra_args`): ASCII alphanumeric plus the
/// safe set `- _ . / @ : =`. Anything else (spaces, shell metacharacters,
/// quotes) is rejected so a hostile token can never split into extra arguments
/// or smuggle injection characters.
pub fn is_allowed_flag_token(token: &str) -> bool {
    !token.is_empty()
        && token.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | '@' | ':' | '=')
        })
}

/// Conservative allowlist for path-shaped values such as a wordlist path:
/// ASCII alphanumeric plus `_ - . /`. Rejects spaces, metacharacters, and any
/// other punctuation. Empty is rejected by the caller before this is reached.
pub fn is_allowed_path(path: &str) -> bool {
    !path.is_empty()
        && path
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reject_metacharacters_flags_shell_chars() {
        for bad in [
            "find; rm -rf /",
            "`whoami`",
            "$(id)",
            "a|b",
            "a&b",
            "line1\nline2",
            "back\\slash",
            "quote\"d",
            "quote'd",
        ] {
            assert!(
                reject_metacharacters(bad, "x").is_err(),
                "should reject {bad}"
            );
        }
        // Passwords with ordinary punctuation are accepted by the guard.
        assert!(reject_metacharacters("P@ssw0rd!#%^*()", "password").is_ok());
        assert!(reject_metacharacters("find", "command").is_ok());
    }

    #[test]
    fn allowed_flag_token_accepts_safe_set() {
        assert!(is_allowed_flag_token("-scheme"));
        assert!(is_allowed_flag_token("CA=corp-ca"));
        assert!(is_allowed_flag_token("user@corp.local"));
        assert!(is_allowed_flag_token("/tmp/out.json"));
        assert!(is_allowed_flag_token("dc-ip:10.0.0.1"));
    }

    #[test]
    fn allowed_flag_token_rejects_unsafe_or_empty() {
        assert!(!is_allowed_flag_token(""));
        assert!(!is_allowed_flag_token("a b"));
        assert!(!is_allowed_flag_token("a;b"));
        assert!(!is_allowed_flag_token("a|b"));
        assert!(!is_allowed_flag_token("$(id)"));
        assert!(!is_allowed_flag_token("a\"b"));
    }

    #[test]
    fn allowed_path_accepts_path_shapes() {
        assert!(is_allowed_path("users.txt"));
        assert!(is_allowed_path("/usr/share/wordlists/users.txt"));
        assert!(is_allowed_path("list-1_final.txt"));
    }

    #[test]
    fn allowed_path_rejects_metacharacters_and_spaces() {
        assert!(!is_allowed_path(""));
        assert!(!is_allowed_path("users.txt; rm -rf /"));
        assert!(!is_allowed_path("my list.txt"));
        assert!(!is_allowed_path("list$(id)"));
        assert!(!is_allowed_path("user@corp")); // '@' not allowed in paths
    }
}
