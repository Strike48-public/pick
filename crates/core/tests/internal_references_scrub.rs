//! Regression guard for the internal-reference scrub (PR #477 review).
//!
//! The scrub removed internal hostnames, lab credentials, workstation paths
//! and captured credentials from the tree, but nothing prevented them from
//! coming back: a mutation that reintroduced `discoball.strike48.engineering`
//! into a doc comment left the whole suite green. This test walks the repo and
//! fails if any denylisted string reappears in a tracked file.
//!
//! The denylist literals are assembled from fragments (concat!) so this file
//! does not itself contain the joined strings it forbids.

use std::path::{Path, PathBuf};

/// Denylisted strings, each built from fragments so the joined value never
/// appears in this source file.
fn denylist() -> Vec<(&'static str, &'static str)> {
    vec![
        ("internal hostname (build host)", concat!("discoball", ".strike48.engineering")),
        ("internal hostname (demo host)", concat!("jt-demo", "-01.strike48.engineering")),
        ("internal hostname (default ws)", concat!("default", ".strike48.engineering")),
        ("shared lab SSH password", concat!("sshpass -p ", "engineering")),
        ("workstation absolute path", concat!("/home/", "jtomek")),
        ("workstation absolute path", concat!("/home/", "jadams")),
        ("captured tenant UUID", concat!("019f86b4", "-d2bf-7f56-89cf-30485d8a956b")),
        ("captured realm slug", concat!("personal-", "f668ca45dbb0")),
        ("captured OTT token", concat!("ott_", "8Ucs8wG8RRMX")),
    ]
}

fn is_skipped(dir: &Path, name: &str) -> bool {
    matches!(name, ".git" | "target" | "node_modules" | ".forge-target")
        || dir.ends_with("docs/archive") // frozen historical snapshots
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if path.is_dir() {
            if !is_skipped(&path, &name) {
                walk(&path, out);
            }
        } else if name != "internal_references_scrub.rs" {
            out.push(path);
        }
    }
}

#[test]
fn no_internal_references_regress_into_the_tree() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest.parent().and_then(Path::parent).expect("repo root");
    let mut files = Vec::new();
    walk(repo_root, &mut files);
    assert!(
        files.len() > 500,
        "walk found only {} files; the repo root is wrong: {}",
        files.len(),
        repo_root.display()
    );

    let denylist = denylist();
    let mut hits: Vec<String> = Vec::new();
    for path in &files {
        let Ok(content) = std::fs::read_to_string(path) else {
            continue; // binary files
        };
        let lower = content.to_lowercase();
        for (label, pattern) in &denylist {
            if lower.contains(&pattern.to_lowercase()) {
                hits.push(format!("{}: {} ({})", path.display(), pattern, label));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "internal references regressed into the tree (rotate/scrub before committing):\n{}",
        hits.join("\n")
    );
}
