//! Regression guard for the internal-reference scrub (pick#477).
//!
//! The scrub removed internal hostnames, a shared lab credential, lab host
//! addresses, workstation paths and captured tenant credentials from the
//! public tree. This test fails if any of them, or anything of the same class,
//! comes back.
//!
//! The guard must not re-publish what it forbids, so this file holds none of
//! the scrubbed values in any recoverable form:
//!
//! * Generic classes are matched by shape, and the pattern carries no secret:
//!   workstation paths (`/home/<name>/`, `/Users/<name>/`) and `sshpass -p`
//!   followed by a literal password in any quoting.
//! * Specific values are matched by SHA-256 digest. Tokens of the right shape
//!   (dotted hostnames, UUIDs, 12-hex realm ids, OTT prefixes, IPv4 addresses)
//!   are hashed and compared, so the digests identify the values without
//!   spelling them.
//!
//! A digest of a low-entropy value (a zone name, a private IPv4 address) stops
//! the value from being restated or grepped. It does not stop a determined
//! guess. Every scrubbed value also remains in public git history (pick#514),
//! so this guard protects the tip of the tree only.
//!
//! Scope: every file `git ls-files` reports as tracked, or untracked and not
//! ignored. That includes `docs/archive/` and this file. Gitignored files
//! (`.env`, `target/`) are out of scope because they cannot be committed by
//! accident.

use regex::Regex;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Internal DNS zones as (label count, SHA-256 of the lowercase zone). A
/// hostname matches when its suffix with that many labels hashes equal.
const INTERNAL_ZONES: &[(usize, &str)] = &[(
    2,
    "06d4e6c5da0606c21b4a1db9e17028650f1a15c814828ca4f87ba0ac7e002658",
)];

/// Tenant UUIDs removed by the scrub (`.env.example`, `scripts/connect.sh`,
/// the pre-approval test fixture), lowercase and hyphenated.
const TENANT_UUIDS: &[&str] = &[
    "2e7c4d219888bcd49b6fe3505625a6a28d77964d375a31cc4232c988cfb05266",
    "95ca9024a29e6cddb8c16733645077d835e683305be045a83d47e417987a0eb9",
    "f4f0748e1f289c7050a9719d2fbd47eaae42cf790e204c92f7dd334795a52bd0",
];

/// The 12-hex id of the captured realm slug, matched with any slug prefix.
const REALM_IDS: &[&str] = &["0feb2a639042d7c87bbd64a15e8b726df61d6a1b39aa4df5fb59f710c69599e1"];

/// The captured OTT token, as `ott_` plus its first 12 characters.
const OTT_PREFIXES: &[&str] = &["71c987e92824408a85c378415ba28809b5c03b499a3ec2b3925fc489bed8f253"];

/// Lab host IPv4 addresses removed by the scrub. Flagged in every file.
const LAB_HOSTS: &[&str] = &[
    "e940ccce56c80c75ed9813278cf1f88ca5130087a7fae48fc12d30c83f79fffa",
    "cae96c9951ea931ed60eca933c0714576e564c1b7789189ac63a4feb509ba139",
    "e5406b86ec78c2821922a7d91884a44082b399596381993b4222c00eb0ad4a1d",
];

/// The lab network's first two octets (`a.b`). Any address in it is flagged;
/// examples use RFC 5737 documentation addresses (192.0.2.0/24) instead.
const LAB_NET_PREFIX: &str = "d18db89633de9e2e23fe81e7f394959c8da7f6c8ea86d68733462eab6f78146e";

/// Placeholder account names that are fine after `/home/` or `/Users/`.
const GENERIC_HOME_NAMES: &[&str] = &[
    "user",
    "username",
    "runner",
    "ubuntu",
    "foo",
    "example",
    "me",
    "you",
    "name",
    "shared",
    "linuxbrew",
];

/// Literal `sshpass -p` values that are known redaction-test fixtures.
const FIXTURE_PASSWORDS: &[&str] = &["s3cr3t"];

const LAB_NET: &str = "lab network address (use RFC 5737 192.0.2.0/24)";

/// The digest tables, passed in so the matcher can be tested with synthetic
/// values.
struct Pins<'a> {
    zones: &'a [(usize, &'a str)],
    uuids: &'a [&'a str],
    realm_ids: &'a [&'a str],
    ott_prefixes: &'a [&'a str],
    lab_hosts: &'a [&'a str],
    lab_net_prefix: &'a str,
}

const PRODUCTION_PINS: Pins<'static> = Pins {
    zones: INTERNAL_ZONES,
    uuids: TENANT_UUIDS,
    realm_ids: REALM_IDS,
    ott_prefixes: OTT_PREFIXES,
    lab_hosts: LAB_HOSTS,
    lab_net_prefix: LAB_NET_PREFIX,
};

struct Rules {
    home: Regex,
    sshpass: Regex,
    host: Regex,
    uuid: Regex,
    hex12: Regex,
    ott: Regex,
    ipv4: Regex,
}

impl Rules {
    fn new() -> Self {
        let re = |p: &str| Regex::new(p).expect("valid guard regex");
        Rules {
            home: re(r"/(?:home|Users)/([A-Za-z0-9._-]+)"),
            sshpass: re(r#"sshpass\s+-p\s*(?:'([^']*)'|"([^"]*)"|([^\s'"`]+))?"#),
            host: re(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+"),
            uuid: re(
                r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            ),
            hex12: re(r"(?i)\b[0-9a-f]{12}\b"),
            ott: re(r"ott_[A-Za-z0-9]{12}"),
            ipv4: re(r"(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}"),
        }
    }
}

fn sha256_hex(s: &str) -> String {
    format!("{:x}", Sha256::digest(s.as_bytes()))
}

fn line_of(text: &str, offset: usize) -> usize {
    text[..offset].matches('\n').count() + 1
}

fn is_generic_home(name: &str) -> bool {
    let lower = name.to_lowercase();
    !lower.chars().any(|c| c.is_ascii_alphanumeric())
        || GENERIC_HOME_NAMES.contains(&lower.as_str())
}

fn is_placeholder_password(raw: &str) -> bool {
    let v = raw.trim_start_matches(['\\', '\'', '"']);
    v.is_empty() || v.starts_with(['<', '$', '{']) || FIXTURE_PASSWORDS.contains(&v)
}

/// Generic classes: workstation paths and literal `sshpass -p` passwords.
fn scan_generic(rules: &Rules, text: &str, out: &mut Vec<(usize, &'static str)>) {
    for c in rules.home.captures_iter(text) {
        if !is_generic_home(&c[1]) {
            out.push((
                line_of(text, c.get(0).unwrap().start()),
                "workstation home path",
            ));
        }
    }
    for c in rules.sshpass.captures_iter(text) {
        let value = c
            .get(1)
            .or(c.get(2))
            .or(c.get(3))
            .map_or("", |m| m.as_str());
        if !is_placeholder_password(value) {
            out.push((
                line_of(text, c.get(0).unwrap().start()),
                "literal sshpass password",
            ));
        }
    }
}

/// Hostnames under an internal zone, matched by suffix digest.
fn scan_hosts(rules: &Rules, pins: &Pins, text: &str, out: &mut Vec<(usize, &'static str)>) {
    for m in rules.host.find_iter(text) {
        let labels: Vec<String> = m
            .as_str()
            .to_lowercase()
            .split('.')
            .map(String::from)
            .collect();
        for (count, digest) in pins.zones {
            if labels.len() >= *count
                && sha256_hex(&labels[labels.len() - count..].join(".")) == *digest
            {
                out.push((line_of(text, m.start()), "hostname in an internal zone"));
            }
        }
    }
}

/// Specific captured values: tenant UUIDs, realm ids and OTT prefixes.
fn scan_pinned(rules: &Rules, pins: &Pins, text: &str, out: &mut Vec<(usize, &'static str)>) {
    // (pattern, digests, kind, case-sensitive). OTT tokens are case-sensitive.
    let tables: [(&Regex, &[&str], &'static str, bool); 3] = [
        (&rules.uuid, pins.uuids, "scrubbed tenant UUID", false),
        (&rules.hex12, pins.realm_ids, "scrubbed realm id", false),
        (&rules.ott, pins.ott_prefixes, "scrubbed OTT token", true),
    ];
    for (re, digests, kind, case_sensitive) in tables {
        for m in re.find_iter(text) {
            let token = if case_sensitive {
                m.as_str().to_string()
            } else {
                m.as_str().to_lowercase()
            };
            if digests.contains(&sha256_hex(&token).as_str()) {
                out.push((line_of(text, m.start()), kind));
            }
        }
    }
}

/// Lab hosts (everywhere) and lab-network addresses (reported as `LAB_NET`).
fn scan_ipv4(rules: &Rules, pins: &Pins, text: &str, out: &mut Vec<(usize, &'static str)>) {
    for c in rules.ipv4.captures_iter(text) {
        let line = line_of(text, c.get(0).unwrap().start());
        if pins.lab_hosts.contains(&sha256_hex(&c[0]).as_str()) {
            out.push((line, "scrubbed lab host address"));
        } else if sha256_hex(&format!("{}.{}", &c[1], &c[2])) == pins.lab_net_prefix {
            out.push((line, LAB_NET));
        }
    }
}

fn scan_text(rules: &Rules, pins: &Pins, text: &str) -> Vec<(usize, &'static str)> {
    let mut out = Vec::new();
    scan_generic(rules, text, &mut out);
    scan_hosts(rules, pins, text, &mut out);
    scan_pinned(rules, pins, text, &mut out);
    scan_ipv4(rules, pins, text, &mut out);
    out
}

fn repo_root() -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(Path::parent)
        .expect("repo root")
        .to_path_buf()
}

/// Tracked files plus untracked files that are not ignored. Fails loudly
/// rather than passing when git cannot enumerate the tree.
fn repo_files(root: &Path) -> Vec<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ])
        .output()
        .expect("the scrub guard needs git on PATH to enumerate the tree");
    assert!(
        out.status.success(),
        "git ls-files failed in {}: {}",
        root.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    let files: HashSet<String> = String::from_utf8_lossy(&out.stdout)
        .split('\0')
        .filter(|p| !p.is_empty())
        .map(String::from)
        .collect();
    let mut files: Vec<String> = files.into_iter().collect();
    files.sort();
    files
}

/// File content as lossy UTF-8, so non-UTF-8 files are still scanned. A
/// symlink is scanned as its target path. Directories (submodules) and files
/// deleted from the working tree yield `None`.
fn read_text(root: &Path, rel: &str) -> Option<String> {
    let path = root.join(rel);
    let meta = std::fs::symlink_metadata(&path).ok()?;
    if meta.file_type().is_symlink() {
        return std::fs::read_link(&path)
            .ok()
            .map(|t| t.to_string_lossy().into_owned());
    }
    if meta.is_dir() {
        return None;
    }
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("cannot read {rel}: {e}"));
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

#[test]
fn no_internal_references_regress_into_the_tree() {
    let root = repo_root();
    let files = repo_files(&root);
    assert!(
        files.len() > 500,
        "git listed only {} files; the repo root is wrong: {}",
        files.len(),
        root.display()
    );

    let rules = Rules::new();
    let mut findings: Vec<String> = Vec::new();
    for rel in &files {
        let Some(text) = read_text(&root, rel) else {
            continue;
        };
        for (line, kind) in scan_text(&rules, &PRODUCTION_PINS, &text) {
            findings.push(format!("{rel}:{line}: {kind}"));
        }
    }
    assert!(
        findings.is_empty(),
        "internal references in the tree (scrub them; rotate anything that was live):\n{}",
        findings.join("\n")
    );
}

/// The matcher itself, against synthetic values only. Samples that would trip
/// the tree scan of this file are assembled at runtime.
#[test]
fn matcher_flags_each_class_and_spares_placeholders() {
    let j = |parts: &[&str]| parts.concat();
    let zone = sha256_hex("corp.invalid");
    let uuid = sha256_hex("12345678-90ab-cdef-1234-567890abcdef");
    let realm = sha256_hex("abcdef012345");
    let ott = sha256_hex("ott_AbCdEf123456");
    let host = sha256_hex("198.51.100.7");
    let pins = Pins {
        zones: &[(2, zone.as_str())],
        uuids: &[uuid.as_str()],
        realm_ids: &[realm.as_str()],
        ott_prefixes: &[ott.as_str()],
        lab_hosts: &[host.as_str()],
        lab_net_prefix: &sha256_hex("203.0"),
    };
    let rules = Rules::new();
    let kinds = |text: &str| -> Vec<&'static str> {
        scan_text(&rules, &pins, text)
            .into_iter()
            .map(|(_, k)| k)
            .collect()
    };

    let flagged = [
        (j(&["cd /ho", "me/alice/src"]), "workstation home path"),
        (j(&["open /Us", "ers/bob.smith/x"]), "workstation home path"),
        (
            j(&["sshp", "ass -p 'hunter2' ssh x"]),
            "literal sshpass password",
        ),
        (
            j(&["sshp", "ass -p\"hunter2\" ssh x"]),
            "literal sshpass password",
        ),
        (
            j(&["sshp", "ass -p hunter2 ssh x"]),
            "literal sshpass password",
        ),
        (
            "wss://Build.CORP.invalid:443".to_string(),
            "hostname in an internal zone",
        ),
        (
            "tenant 12345678-90AB-cdef-1234-567890abcdef".to_string(),
            "scrubbed tenant UUID",
        ),
        ("realm team-abcdef012345".to_string(), "scrubbed realm id"),
        (
            "token ott_AbCdEf123456-rest".to_string(),
            "scrubbed OTT token",
        ),
        (
            "ssh lab@198.51.100.7".to_string(),
            "scrubbed lab host address",
        ),
        ("subnet 203.0.113.0/24".to_string(), LAB_NET),
    ];
    for (text, kind) in &flagged {
        assert_eq!(kinds(text), vec![*kind], "expected {kind} for {text:?}");
    }

    let spared = [
        "/home/user/project and /mnt/c/Users/foo/bar and /home/$USER/x",
        "sshpass -p '<pw>' and sshpass -p \"$PW\" and sshpass -p '{p}' and sshpass -p 's3cr3t'",
        "wss://pick.example.com and corp.invalid.example.com",
        "00000000-0000-0000-0000-000000000000 and ott_TEST_FIXTURE and 192.0.2.1",
    ];
    for text in spared {
        assert!(
            kinds(text).is_empty(),
            "false positive on {text:?}: {:?}",
            kinds(text)
        );
    }
}
