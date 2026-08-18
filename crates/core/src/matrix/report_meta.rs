//! Parser for the optional YAML frontmatter Pick's easy-mode reports carry.
//! Every field is optional and malformed input degrades to `Default` — the
//! renderer/UI must never break on a bad or absent block.

use serde::Deserialize;

use crate::rendering::split_frontmatter;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct SeverityCounts {
    pub critical: Option<u32>,
    pub high: Option<u32>,
    pub medium: Option<u32>,
    pub low: Option<u32>,
    pub info: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReportFinding {
    pub severity: Option<String>,
    pub title: Option<String>,
    pub body: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ReportMeta {
    pub title: Option<String>,
    pub scope: Option<String>,
    pub source: Option<String>,
    pub hosts: Option<u32>,
    pub services: Option<u32>,
    #[serde(default)]
    pub severity: SeverityCounts,
    #[serde(default)]
    pub findings: Vec<ReportFinding>,
}

/// Which color bucket a report's severity badge falls into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BadgeKind {
    Critical,
    High,
    Medium,
    Low,
    Info,
    Clean,
}

/// A rendered severity badge: a short label and its color bucket.
#[derive(Debug, Clone)]
pub struct SeverityBadge {
    pub label: String,
    pub kind: BadgeKind,
}

impl ReportMeta {
    /// Parse a document's frontmatter. Returns `Some(meta)` only when the
    /// content actually begins with a frontmatter block — malformed YAML inside
    /// a present block degrades to `Some(Default)`, but content with NO
    /// frontmatter returns `None`. Callers use this to distinguish a legacy
    /// report (no badge) from a parsed-but-no-severity report ("clean" badge).
    pub fn parse(content: &str) -> Option<ReportMeta> {
        match split_frontmatter(content) {
            (Some(yaml), _) => Some(serde_yml::from_str(yaml).unwrap_or_default()),
            (None, _) => None,
        }
    }

    /// Highest non-zero severity bucket as a badge, or "clean" when none.
    pub fn badge(&self) -> SeverityBadge {
        let s = &self.severity;
        // critical folds into "high"-red per the spec badge colors, but keep a
        // distinct kind so callers could style it; label uses the bucket name.
        for (n, kind, name) in [
            (s.critical, BadgeKind::Critical, "critical"),
            (s.high, BadgeKind::High, "high"),
            (s.medium, BadgeKind::Medium, "medium"),
            (s.low, BadgeKind::Low, "low"),
            (s.info, BadgeKind::Info, "info"),
        ] {
            if let Some(count) = n {
                if count > 0 {
                    return SeverityBadge {
                        label: format!("{count} {name}"),
                        kind,
                    };
                }
            }
        }
        SeverityBadge {
            label: "clean".to_string(),
            kind: BadgeKind::Clean,
        }
    }

    /// All non-zero severity buckets as badges, highest first. Empty when the
    /// report recorded no findings (callers show a "clean" state themselves).
    /// Used by the Home "Last scan" tile, which lists every bucket (e.g.
    /// "2 high" + "3 medium") rather than just the top one.
    pub fn all_badges(&self) -> Vec<SeverityBadge> {
        let s = &self.severity;
        let mut out = Vec::new();
        for (n, kind, name) in [
            (s.critical, BadgeKind::Critical, "critical"),
            (s.high, BadgeKind::High, "high"),
            (s.medium, BadgeKind::Medium, "medium"),
            (s.low, BadgeKind::Low, "low"),
            (s.info, BadgeKind::Info, "info"),
        ] {
            if let Some(count) = n {
                if count > 0 {
                    out.push(SeverityBadge {
                        label: format!("{count} {name}"),
                        kind,
                    });
                }
            }
        }
        out
    }

    /// True when the report has any critical or high findings.
    pub fn is_high_risk(&self) -> bool {
        self.severity.critical.unwrap_or(0) > 0 || self.severity.high.unwrap_or(0) > 0
    }

    /// Number of findings: `findings.len()` when present, else the sum of the
    /// severity counts.
    pub fn finding_count(&self) -> u32 {
        if !self.findings.is_empty() {
            return self.findings.len() as u32;
        }
        let s = &self.severity;
        s.critical.unwrap_or(0)
            + s.high.unwrap_or(0)
            + s.medium.unwrap_or(0)
            + s.low.unwrap_or(0)
            + s.info.unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = "---\nscope: \"192.168.1.0/24\"\nsource: \"mbp\"\nhosts: 8\nservices: 21\nseverity:\n  high: 2\n  medium: 3\n  low: 1\nfindings:\n  - severity: high\n    title: \"PG exposed\"\n    body: \"fix it\"\n---\n# Body\n";

    #[test]
    fn parses_full_frontmatter() {
        let m = ReportMeta::parse(FULL).expect("frontmatter present");
        assert_eq!(m.scope.as_deref(), Some("192.168.1.0/24"));
        assert_eq!(m.source.as_deref(), Some("mbp"));
        assert_eq!(m.hosts, Some(8));
        assert_eq!(m.services, Some(21));
        assert_eq!(m.severity.high, Some(2));
        assert_eq!(m.findings.len(), 1);
    }

    #[test]
    fn no_frontmatter_is_none() {
        // No frontmatter block -> None (legacy report, no badge).
        assert!(ReportMeta::parse("# just markdown").is_none());
    }

    #[test]
    fn malformed_yaml_is_some_default() {
        // A present-but-broken block still parses to Some(Default) so the
        // report is treated as "had frontmatter" rather than legacy.
        let m = ReportMeta::parse("---\n: : : not yaml\n\t- broken\n---\nbody")
            .expect("frontmatter block present");
        assert!(m.scope.is_none() && m.findings.is_empty());
    }

    #[test]
    fn badge_picks_highest_bucket() {
        let m = ReportMeta::parse("---\nseverity:\n  high: 2\n  medium: 3\n---\nx").unwrap();
        let b = m.badge();
        assert_eq!(b.label, "2 high");
        assert!(matches!(b.kind, BadgeKind::High));
        assert!(m.is_high_risk());
    }

    #[test]
    fn badge_clean_when_no_severity() {
        let m = ReportMeta::parse("---\nscope: x\n---\ny").unwrap();
        assert_eq!(m.badge().label, "clean");
        assert!(matches!(m.badge().kind, BadgeKind::Clean));
        assert!(!m.is_high_risk());
    }

    #[test]
    fn all_badges_lists_every_bucket_highest_first() {
        let m =
            ReportMeta::parse("---\nseverity:\n  high: 2\n  medium: 3\n  low: 1\n---\nx").unwrap();
        let labels: Vec<_> = m.all_badges().into_iter().map(|b| b.label).collect();
        assert_eq!(labels, vec!["2 high", "3 medium", "1 low"]);
        // No severity -> empty (caller renders a "clean" state).
        let clean = ReportMeta::parse("---\nscope: x\n---\ny").unwrap();
        assert!(clean.all_badges().is_empty());
    }

    #[test]
    fn finding_count_prefers_findings_then_severity_sum() {
        let with_findings = ReportMeta::parse(
            "---\nseverity:\n  high: 5\nfindings:\n  - title: a\n  - title: b\n---\nx",
        )
        .unwrap();
        assert_eq!(with_findings.finding_count(), 2);
        let sev_only = ReportMeta::parse("---\nseverity:\n  high: 2\n  low: 1\n---\nx").unwrap();
        assert_eq!(sev_only.finding_count(), 3);
    }
}
