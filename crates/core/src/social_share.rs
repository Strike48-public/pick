//! Social share-intent URLs for the Easy Mode growth loop.
//!
//! Given a public share URL (and optional summary text), build the per-network
//! web-intent URLs that open a pre-filled compose window on X, LinkedIn, or
//! Facebook. These are plain browser links — no SDK, no API keys, no analytics
//! — so they work today on top of the existing public share links. Query
//! parameters are encoded via `reqwest::Url` rather than hand-rolled.
//!
//! NOTE: the *usage-summary* content of the shared card and *share-event
//! tracking* (per issue #284) depend on Pick's analytics (#278) and are NOT
//! part of this module.

use serde::{Deserialize, Serialize};

/// A social network Easy Mode can share a report link to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SocialNetwork {
    X,
    LinkedIn,
    Facebook,
}

impl SocialNetwork {
    /// Stable lowercase key (useful for labels, and later for share-event names).
    pub fn key(self) -> &'static str {
        match self {
            SocialNetwork::X => "x",
            SocialNetwork::LinkedIn => "linkedin",
            SocialNetwork::Facebook => "facebook",
        }
    }

    /// Human-facing button label.
    pub fn label(self) -> &'static str {
        match self {
            SocialNetwork::X => "X",
            SocialNetwork::LinkedIn => "LinkedIn",
            SocialNetwork::Facebook => "Facebook",
        }
    }

    /// All networks, in display order.
    pub fn all() -> [SocialNetwork; 3] {
        [
            SocialNetwork::X,
            SocialNetwork::LinkedIn,
            SocialNetwork::Facebook,
        ]
    }
}

/// Build the web-intent URL that opens a pre-filled compose window for `network`,
/// sharing `share_url` with optional `text`.
///
/// Returns an error only if the resulting intent URL can't be parsed (never
/// expected for the fixed hosts below); callers can treat that as "skip".
pub fn share_intent_url(
    network: SocialNetwork,
    share_url: &str,
    text: &str,
) -> Result<String, String> {
    let base = match network {
        // X (Twitter) intent: text + url both supported.
        SocialNetwork::X => "https://twitter.com/intent/tweet",
        // LinkedIn share dialog: only `url` is honored; text is ignored by LI.
        SocialNetwork::LinkedIn => "https://www.linkedin.com/sharing/share-offsite/",
        // Facebook sharer: only `u` (the URL) is honored.
        SocialNetwork::Facebook => "https://www.facebook.com/sharer/sharer.php",
    };

    let mut url = reqwest::Url::parse(base).map_err(|e| format!("invalid share base URL: {e}"))?;

    {
        let mut qp = url.query_pairs_mut();
        match network {
            SocialNetwork::X => {
                qp.append_pair("url", share_url);
                if !text.is_empty() {
                    qp.append_pair("text", text);
                }
            }
            SocialNetwork::LinkedIn => {
                qp.append_pair("url", share_url);
            }
            SocialNetwork::Facebook => {
                qp.append_pair("u", share_url);
            }
        }
    }

    Ok(url.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x_intent_includes_url_and_text() {
        let out = share_intent_url(SocialNetwork::X, "https://s.test/s/tok", "My scan").unwrap();
        assert!(out.starts_with("https://twitter.com/intent/tweet?"));
        assert!(out.contains("url=https%3A%2F%2Fs.test%2Fs%2Ftok"));
        assert!(out.contains("text=My+scan"));
    }

    #[test]
    fn x_intent_omits_empty_text() {
        let out = share_intent_url(SocialNetwork::X, "https://s.test/s/tok", "").unwrap();
        assert!(out.contains("url="));
        assert!(!out.contains("text="));
    }

    #[test]
    fn linkedin_intent_uses_url_param_only() {
        let out =
            share_intent_url(SocialNetwork::LinkedIn, "https://s.test/s/tok", "ignored").unwrap();
        assert!(out.starts_with("https://www.linkedin.com/sharing/share-offsite/?"));
        assert!(out.contains("url=https%3A%2F%2Fs.test%2Fs%2Ftok"));
        assert!(!out.contains("text="));
    }

    #[test]
    fn facebook_intent_uses_u_param() {
        let out = share_intent_url(SocialNetwork::Facebook, "https://s.test/s/tok", "x").unwrap();
        assert!(out.starts_with("https://www.facebook.com/sharer/sharer.php?"));
        assert!(out.contains("u=https%3A%2F%2Fs.test%2Fs%2Ftok"));
    }

    #[test]
    fn special_chars_in_url_are_encoded() {
        let out =
            share_intent_url(SocialNetwork::X, "https://s.test/s/a b&c=d", "hi there").unwrap();
        // No raw space/ampersand from the payload leaks into the query structure.
        assert!(out.contains("a+b%26c%3Dd") || out.contains("a%20b%26c%3Dd"));
        assert!(out.contains("text=hi+there"));
    }

    #[test]
    fn network_keys_are_stable() {
        assert_eq!(SocialNetwork::X.key(), "x");
        assert_eq!(SocialNetwork::LinkedIn.key(), "linkedin");
        assert_eq!(SocialNetwork::Facebook.key(), "facebook");
    }
}
