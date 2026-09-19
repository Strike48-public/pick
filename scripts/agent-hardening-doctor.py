#!/usr/bin/env python3
"""Doctor validator for pick's agent-hardening controls (C1-C3).

A honeyslop-doctor adaptation (https://github.com/gadievron/honeyslop):
every PR re-verifies that the agent-security controls are present and
wired, so a "cleanup" PR cannot silently strip the defense layers the
review doc (docs/AGENT_HARDENING_REVIEW.md) commits to.

Checks (each maps to a control):

C1 - Seed-channel fail-closed sanitization
  c1.1  evidence_producer.rs must sanitize node text fields at the write
        path (sanitize_node_fields called from push_evidence).
  c1.2  orchestrator seed builders must route the manifest through
        neutralize_manifest_for_seed (defense-in-depth at the agent
        boundary), so a future seed-builder cannot return raw evidence.
  c1.3  sanitize.rs must export NEUTRALIZED (the shared inert token).

C2 - Fail-closed gate + severity hygiene
  c2.1  gate_for_report must reject injection-flagged publishable
        findings (InjectionFlaggedNodes), closing the fail-open gap.
  c2.2  webwright findings must default to Low unless explicitly
        critical/high (severity hygiene), explicit info stays Info, and
        same-title findings merge into the retained node (max severity,
        accumulated descriptions/URLs).

C3 - Session budget envelope + stall detector
  c3.1  a SessionBudget type must exist with check/record/reset.
  c3.2  both connectors (PentestConnector, PickConnector) must reference
        the budget and reset it on begin_scan (via reset_for_new_scan,
        inside the production execute path).
  c3.3  budget defaults must scale with aggression level.

How it verifies (review #453, S4/F3):
- Rust line/block comments are stripped before matching, so a "cleanup"
  PR cannot pass green by commenting a guarded call OUT (a comment is not
  a wired control).
- Call-site patterns are anchored to their PRODUCTION function's body (the
  call must live inside push_evidence / the seed builders / the connector
  execute path), so deleting the real call while leaving `#[cfg(test)]`
  call-sites in place still fails.
- `--self-test` exercises both negative paths against throwaway fixtures,
  so the tripwire is itself guarded.

Non-goals (deliberate, matching honeyslop-doctor's scope discipline):
- Does not prove runtime behavior; the Rust unit tests do that. This is
  a structural presence check so the layers cannot silently vanish.
- C5 canary markers are a later control; when they land, add a marker
  registration check here (see docs/AGENT_HARDENING_REVIEW.md C9 for the
  rotation playbook that same check supports).
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# ------------------------------------------------------------------
# Check catalog.
#
# Each check is a dict:
#   id, desc     - identity and human label
#   files        - repo-relative paths the check inspects (single source of
#                  truth for paths; drives run() so there is no second copy)
#   file_patterns- regexes that must appear anywhere in the (comment-stripped)
#                  file
#   anchored     - list of (fn_name_regex, [patterns]); each pattern must appear
#                  inside the body of a PRODUCTION function whose name matches
#                  fn_name_regex, in the same file. This defeats "delete the real
#                  call, keep the #[cfg(test)] call" because test call-sites live
#                  in other functions.
# ------------------------------------------------------------------

CHECKS: list[dict] = [
    {
        "id": "c1.1",
        "desc": "evidence write path sanitizes node fields",
        "files": ["crates/tools/src/evidence_producer.rs"],
        "file_patterns": [r"fn\s+sanitize_node_fields\b"],
        "anchored": [
            (r"push_evidence", [r"sanitize_node_fields\(&mut node\)\s*;"]),
        ],
    },
    {
        "id": "c1.2",
        "desc": "seed builders route through neutralize_manifest_for_seed (no raw evidence seed)",
        "files": ["crates/core/src/orchestrator.rs"],
        "file_patterns": [r"fn\s+neutralize_manifest_for_seed\b"],
        # Every seed builder must call it, inside its own body — not merely
        # somewhere in the file.
        "anchored": [
            (
                r"build_report_agent_seed_message",
                [r"neutralize_manifest_for_seed\(&mut value\)\s*;"],
            ),
            (
                r"build_validator_seed_message",
                [r"neutralize_manifest_for_seed\(&mut value\)\s*;"],
            ),
        ],
    },
    {
        "id": "c1.3",
        "desc": "sanitize.rs exports the shared inert token",
        "files": ["crates/core/src/sanitize.rs"],
        "file_patterns": [r"pub\s+const\s+NEUTRALIZED\s*:"],
        "anchored": [],
    },
    {
        "id": "c2.1",
        "desc": "gate blocks injection-flagged publishable findings",
        "files": ["crates/core/src/orchestrator.rs"],
        "file_patterns": [r"InjectionFlaggedNodes\s*\{", r"injection_suspected"],
        "anchored": [],
    },
    {
        "id": "c2.2",
        "desc": "webwright severity hygiene + same-title merge",
        "files": ["crates/tools/src/webwright/evidence.rs"],
        "file_patterns": [
            r"Severity::Low\b",
            r"Severity::Info\b",
            r"by_title\b",
            r"severity_rank\b",
        ],
        "anchored": [],
    },
    {
        "id": "c3.1",
        "desc": "SessionBudget type with check/record/reset",
        "files": ["crates/core/src/budget.rs"],
        "file_patterns": [
            r"pub\s+struct\s+SessionBudget\b",
            r"pub\s+async\s+fn\s+check\b",
            r"pub\s+async\s+fn\s+record\b",
            r"pub\s+async\s+fn\s+reset\b",
        ],
        "anchored": [],
    },
    {
        "id": "c3.2",
        "desc": "both connectors hold the budget and reset it on begin_scan",
        "files": [
            "crates/core/src/connector.rs",
            "crates/ui/src/liveview_connector/pick_connector.rs",
        ],
        "file_patterns": [
            r"budget\s*:\s*(?:crate|pentest_core)::budget::SessionBudget",
        ],
        # The begin_scan reset must live in the production execute path, not a
        # test. `execute` (core) / `execute_with_context` (ui) are the seams.
        "anchored": [
            (
                r"execute(?:_with_context)?",
                [r"begin_scan", r"reset_for_new_scan\(\)\.await"],
            ),
        ],
    },
    {
        "id": "c3.3",
        "desc": "budget defaults scale with aggression level",
        "files": ["crates/core/src/budget.rs"],
        "file_patterns": [r"fn\s+default_budget\b"],
        "anchored": [
            (
                r"default_budget",
                [
                    r"AggressionLevel::Conservative",
                    r"AggressionLevel::Balanced",
                    r"AggressionLevel::Aggressive",
                    r"AggressionLevel::Maximum",
                    r"max_executions",
                ],
            ),
        ],
    },
]

# ------------------------------------------------------------------
# Rust-aware text scanning.
#
# The whole point of this doctor is that a control cannot be silently
# removed. A regex over raw file text is trivially defeated (comment the
# call out; leave a test call behind), so we normalize first:
#   * strip line/block comments (nesting-aware), preserving string literals
#     so `"begin_scan"` and friends still match;
#   * skip string/char/raw-string literals when balancing brackets, so a
#     `'}'` char or a format string's braces cannot desync the matcher.
# ------------------------------------------------------------------

_RAW_OPEN = re.compile(r'b?r(#*)"')
_CHAR_LIT = re.compile(r"'(?:\\(?:x[0-9A-Fa-f]{2}|u\{[0-9A-Fa-f]+\}|.)|[^'\\\n])'")


def _skip_dquote(text: str, i: int) -> int:
    """`text[i]` is `"`; return the index just past the closing quote."""
    i += 1
    n = len(text)
    while i < n:
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if c == '"':
            return i + 1
        i += 1
    return i


def _skip_char_or_lifetime(text: str, i: int) -> int:
    """`text[i]` is `'`; skip a char literal, or a lifetime tick (one char)."""
    m = _CHAR_LIT.match(text, i)
    if m:
        return m.end()
    return i + 1


def _skip_literal(text: str, i: int):
    """If a string/char/raw-string literal starts at `i`, return its end index;
    otherwise None. Handles r"...", r#"..."#, b"...", br#"..."#, and chars."""
    c = text[i]
    if c in "rb":
        m = _RAW_OPEN.match(text, i)
        if m:
            close = '"' + m.group(1)
            end = text.find(close, m.end())
            return len(text) if end == -1 else end + len(close)
        if c == "b" and i + 1 < len(text) and text[i + 1] == '"':
            return _skip_dquote(text, i + 1)
        return None
    if c == '"':
        return _skip_dquote(text, i)
    if c == "'":
        return _skip_char_or_lifetime(text, i)
    return None


def _strip_comments(text: str) -> str:
    """Remove Rust line and (nesting-aware) block comments, preserving string
    and char literals verbatim."""
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        lit_end = _skip_literal(text, i)
        if lit_end is not None:
            out.append(text[i:lit_end])
            i = lit_end
            continue
        if text.startswith("//", i):
            nl = text.find("\n", i)
            i = n if nl == -1 else nl
            continue
        if text.startswith("/*", i):
            depth = 1
            j = i + 2
            while j < n and depth:
                if text.startswith("/*", j):
                    depth += 1
                    j += 2
                elif text.startswith("*/", j):
                    depth -= 1
                    j += 2
                else:
                    j += 1
            i = j
            continue
        out.append(text[i])
        i += 1
    return "".join(out)


def _find_matching(text: str, open_idx: int) -> int:
    """Index of the bracket matching the opener at `open_idx`, skipping literals.
    Returns -1 if unbalanced."""
    pairs = {"(": ")", "[": "]", "{": "}"}
    closes = set(pairs.values())
    stack = [pairs[text[open_idx]]]
    i = open_idx + 1
    n = len(text)
    while i < n and stack:
        lit_end = _skip_literal(text, i)
        if lit_end is not None:
            i = lit_end
            continue
        c = text[i]
        if c in pairs:
            stack.append(pairs[c])
        elif c in closes:
            if stack and stack[-1] == c:
                stack.pop()
        i += 1
    return i - 1 if not stack else -1


def _extract_fn_bodies(text: str, name_regex: str) -> str:
    """Return the concatenated bodies of every `fn <name_regex>(...)` definition
    in `text` (comment-stripped input expected). Trait-method declarations with
    no body (`fn foo();`) contribute nothing."""
    header = re.compile(r"\bfn\s+(?:%s)\s*(?:<[^>]*>)?\s*\(" % name_regex)
    bodies: list[str] = []
    for m in header.finditer(text):
        paren_open = m.end() - 1  # the '(' the header ends on
        paren_close = _find_matching(text, paren_open)
        if paren_close == -1:
            continue
        brace_open = _next_body_brace(text, paren_close + 1)
        if brace_open == -1:
            continue
        brace_close = _find_matching(text, brace_open)
        if brace_close == -1:
            continue
        bodies.append(text[brace_open : brace_close + 1])
    return "\n".join(bodies)


def _next_body_brace(text: str, start: int) -> int:
    """From `start` (just past a fn's parameter list), return the index of the
    body's opening `{`, or -1 if a `;` (declaration, no body) is hit first."""
    i = start
    n = len(text)
    while i < n:
        lit_end = _skip_literal(text, i)
        if lit_end is not None:
            i = lit_end
            continue
        c = text[i]
        if c == "{":
            return i
        if c == ";":
            return -1
        i += 1
    return -1


def _missing_for_check(check: dict, root: Path) -> list[str]:
    """Return the list of unmet requirements for `check` (empty = all present)."""
    missing: list[str] = []
    for rel in check["files"]:
        path = root.joinpath(*rel.split("/"))
        if not path.exists():
            missing.append(f"file missing: {rel}")
            continue
        text = _strip_comments(path.read_text(encoding="utf-8", errors="replace"))
        for pat in check.get("file_patterns", []):
            if re.search(pat, text) is None:
                missing.append(f"{rel}: not found: {pat}")
        for fn_regex, patterns in check.get("anchored", []):
            body = _extract_fn_bodies(text, fn_regex)
            if not body:
                missing.append(f"{rel}: production fn /{fn_regex}/ not found")
                continue
            for pat in patterns:
                if re.search(pat, body) is None:
                    missing.append(f"{rel}: not found in fn /{fn_regex}/: {pat}")
    return missing


def run(root: Path) -> bool:
    ok = True
    for check in CHECKS:
        missing = _missing_for_check(check, root)
        if missing:
            ok = False
            print(f"FAIL {check['id']} — {check['desc']}")
            for m in missing:
                print(f"  missing: {m}")
        else:
            print(f"ok   {check['id']} — {check['desc']}")
    return ok


# ------------------------------------------------------------------
# Self-test: prove the tripwire actually trips (review #453, S4/F3).
#
# Builds a throwaway fixture tree where every control is present (doctor
# must pass), then applies the two evasion modes the review demonstrated
# on the real PR and asserts the doctor now FAILS:
#   (1) comment the guarded call out            -> must fail
#   (2) delete the production call, keep a test  -> must fail
# ------------------------------------------------------------------

# Minimal fixture files (regex-scanned, not compiled) — one production call
# site plus a #[cfg(test)] call site so mode (2) has a test remnant to leave.
_FIXTURE_EVIDENCE = """\
pub fn push_evidence(node: EvidenceNode) -> Result<(), BufferFullError> {
    let mut node = node;
    let report = sanitize_node_fields(&mut node);
    let _ = report;
    Ok(())
}

pub fn sanitize_node_fields(node: &mut EvidenceNode) -> SanitizeReport {
    SanitizeReport::default()
}

#[cfg(test)]
mod tests {
    #[test]
    fn sanitize_node_fields_neutralizes() {
        let mut node = EvidenceNode::default();
        let report = sanitize_node_fields(&mut node);
        let _ = report;
    }
}
"""

_FIXTURE_ORCHESTRATOR = """\
fn neutralize_manifest_for_seed(manifest_value: &mut serde_json::Value) -> bool {
    let _ = manifest_value;
    false
}

pub fn build_report_agent_seed_message(manifest: &Manifest) -> String {
    let mut value = to_value(manifest);
    let injection_suspected = neutralize_manifest_for_seed(&mut value);
    let _ = injection_suspected;
    String::new()
}

pub fn build_validator_seed_message(manifest: &Manifest) -> Result<String, String> {
    let mut value = to_value(manifest);
    let injection_suspected = neutralize_manifest_for_seed(&mut value);
    let _ = injection_suspected;
    Ok(String::new())
}

pub enum GateError {
    InjectionFlaggedNodes { nodes: Vec<String> },
}
"""

_FIXTURE_SANITIZE = 'pub const NEUTRALIZED: &str = "[neutralized-instruction]";\n'

_FIXTURE_WEBWRIGHT = """\
fn build_finding() {
    let severity = Severity::Low;
    let info = Severity::Info;
    fn severity_rank(s: Severity) -> u8 { 0 }
    let mut by_title = std::collections::HashMap::new();
    let _ = (severity, info, &mut by_title);
}
"""

_FIXTURE_BUDGET = """\
pub struct SessionBudget {
    inner: u32,
}

impl SessionBudget {
    pub async fn check(&self) -> bool { true }
    pub async fn record(&self, _made_progress: bool) {}
    pub async fn reset(&self) {}
    pub async fn reset_for_new_scan(&self) -> bool { true }
}

pub fn default_budget(level: AggressionLevel) -> BudgetConfig {
    match level {
        AggressionLevel::Conservative => BudgetConfig { max_executions: 200 },
        AggressionLevel::Balanced => BudgetConfig { max_executions: 500 },
        AggressionLevel::Aggressive => BudgetConfig { max_executions: 1_000 },
        AggressionLevel::Maximum => BudgetConfig { max_executions: 2_000 },
    }
}
"""

_FIXTURE_CONNECTOR = """\
pub struct PentestConnector {
    budget: crate::budget::SessionBudget,
}

impl PentestConnector {
    fn execute(&self, request: Value) -> SdkResult<Value> {
        let tool_name = request.get("tool").and_then(|v| v.as_str()).unwrap_or("");
        if tool_name == "begin_scan" {
            self.budget.reset_for_new_scan().await;
        }
        Ok(Value::Null)
    }
}
"""

_FIXTURE_PICK_CONNECTOR = """\
pub(crate) struct PickConnector {
    pub budget: pentest_core::budget::SessionBudget,
}

impl PickConnector {
    fn execute_with_context<'a>(&'a self, request: Value) -> Result<Value> {
        let tool_name = request.get("tool").and_then(|v| v.as_str()).unwrap_or("");
        if tool_name == "begin_scan" {
            self.budget.reset_for_new_scan().await;
        }
        Ok(Value::Null)
    }
}
"""

_FIXTURES = {
    "crates/tools/src/evidence_producer.rs": _FIXTURE_EVIDENCE,
    "crates/core/src/orchestrator.rs": _FIXTURE_ORCHESTRATOR,
    "crates/core/src/sanitize.rs": _FIXTURE_SANITIZE,
    "crates/tools/src/webwright/evidence.rs": _FIXTURE_WEBWRIGHT,
    "crates/core/src/budget.rs": _FIXTURE_BUDGET,
    "crates/core/src/connector.rs": _FIXTURE_CONNECTOR,
    "crates/ui/src/liveview_connector/pick_connector.rs": _FIXTURE_PICK_CONNECTOR,
}

# The one production call site that both evasion modes target.
_GUARDED_CALL = "    let report = sanitize_node_fields(&mut node);\n"


def _write_fixture(root: Path) -> None:
    for rel, content in _FIXTURES.items():
        path = root.joinpath(*rel.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def _self_test() -> bool:
    import tempfile

    ep_rel = "crates/tools/src/evidence_producer.rs"
    ok = True

    def expect(got: bool, want: bool, label: str) -> None:
        nonlocal ok
        status = "PASS" if got == want else "FAIL"
        if got != want:
            ok = False
        print(f"  [{status}] {label} (doctor {'OK' if got else 'FAIL'}, want {'OK' if want else 'FAIL'})")

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        ep = root.joinpath(*ep_rel.split("/"))

        print("self-test 0: pristine fixture must pass")
        _write_fixture(root)
        good = ep.read_text(encoding="utf-8")
        assert _GUARDED_CALL in good, "fixture drifted from the guarded-call constant"
        expect(run(root), True, "pristine fixture")

        print("self-test 1: guarded call commented OUT must fail (comment stripping)")
        _write_fixture(root)
        ep.write_text(
            good.replace(_GUARDED_CALL, "    // " + _GUARDED_CALL.lstrip(), 1),
            encoding="utf-8",
        )
        expect(run(root), False, "commented-out production call")

        print("self-test 2: production call deleted, test call remains, must fail (anchoring)")
        _write_fixture(root)
        ep.write_text(good.replace(_GUARDED_CALL, "", 1), encoding="utf-8")
        expect(run(root), False, "production call removed with test remnant")

    return ok


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=REPO_ROOT,
        help="repo root (defaults to the repo containing this script)",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run the tripwire's own negative-path fixtures instead of the repo",
    )
    args = parser.parse_args()

    if args.self_test:
        print("= pick agent-hardening doctor: self-test =")
        ok = _self_test()
        print("=" * 32)
        if ok:
            print("self-test: OK — tripwire trips on both evasion modes")
            return 0
        print("self-test: FAILED — tripwire is bypassable")
        return 1

    print("= pick agent-hardening doctor =")
    ok = run(args.root)
    print("=" * 32)
    if ok:
        print("doctor: OK")
        return 0
    print("doctor: FAILED — one or more agent-hardening controls are missing")
    return 1


if __name__ == "__main__":
    sys.exit(main())
