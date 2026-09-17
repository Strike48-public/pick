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
        critical/high (severity hygiene), and dedupe identical titles.

C3 - Session budget envelope + stall detector
  c3.1  a SessionBudget type must exist with check/record/reset.
  c3.2  both connectors (PentestConnector, PickConnector) must reference
        the budget and reset it on begin_scan.
  c3.3  budget defaults must scale with aggression level.

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
# C1: seed-channel sanitization
# ------------------------------------------------------------------

C1_1 = (
    "c1.1",
    "evidence write path sanitizes node fields",
    "crates/tools/src/evidence_producer.rs",
    [
        r"fn\s+sanitize_node_fields\b",
        r"sanitize_node_fields\(&mut node\)\s*;",
    ],
)

C1_2 = (
    "c1.2",
    "seed builders route through neutralize_manifest_for_seed (no raw evidence seed)",
    "crates/core/src/orchestrator.rs",
    [
        r"fn\s+neutralize_manifest_for_seed\b",
        r"neutralize_manifest_for_seed\(&mut value\)\s*;",
        # Every seed builder must call it: both report and validator seeds.
        r"build_report_agent_seed_message",
        r"build_validator_seed_message",
    ],
)

C1_3 = (
    "c1.3",
    "sanitize.rs exports the shared inert token",
    "crates/core/src/sanitize.rs",
    [
        r"pub\s+const\s+NEUTRALIZED\s*:",
    ],
)

# ------------------------------------------------------------------
# C2: gate + severity hygiene
# ------------------------------------------------------------------

C2_1 = (
    "c2.1",
    "gate blocks injection-flagged publishable findings",
    "crates/core/src/orchestrator.rs",
    [
        r"InjectionFlaggedNodes\s*\{",
        r"injection_suspected",
    ],
)

C2_2 = (
    "c2.2",
    "webwright severity hygiene + dedupe",
    "crates/tools/src/webwright/evidence.rs",
    [
        r"Severity::Low\b",
        r"seen_titles\b",
    ],
)

# ------------------------------------------------------------------
# C3: budget envelope
# ------------------------------------------------------------------

C3_1 = (
    "c3.1",
    "SessionBudget type with check/record/reset",
    "crates/core/src/budget.rs",
    [
        r"pub\s+struct\s+SessionBudget\b",
        r"pub\s+async\s+fn\s+check\b",
        r"pub\s+async\s+fn\s+record\b",
        r"pub\s+async\s+fn\s+reset\b",
    ],
)

C3_2 = (
    "c3.2",
    "both connectors hold and reset the budget",
    "connectors",
    [
        r"budget\s*:\s*(?:crate|pentest_core)::budget::SessionBudget",
        r"budget\.reset\(\)\.await",
    ],
)


def _check_file(path: Path, patterns: list[str]) -> list[str]:
    """Return list of missing patterns in `path` (empty = all present)."""
    if not path.exists():
        return [f"file missing: {path}"]
    text = path.read_text(encoding="utf-8", errors="replace")
    return [p for p in patterns if re.search(p, text) is None]


def run(root: Path) -> bool:
    ok = True

    def verify(check: tuple, paths: list[Path]) -> None:
        nonlocal ok
        cid, desc, _loc, patterns = check
        missing: list[str] = []
        for path in paths:
            missing += _check_file(path, patterns)
        if missing:
            ok = False
            print(f"FAIL {cid} — {desc}")
            for m in missing:
                print(f"  missing: {m}")
        else:
            print(f"ok   {cid} — {desc}")

    # C1 checks: main file + both connectors referencing the budget.
    verify(C1_1, [root / "crates" / "tools" / "src" / "evidence_producer.rs"])
    verify(C1_2, [root / "crates" / "core" / "src" / "orchestrator.rs"])
    verify(C1_3, [root / "crates" / "core" / "src" / "sanitize.rs"])
    verify(C2_1, [root / "crates" / "core" / "src" / "orchestrator.rs"])
    verify(C2_2, [root / "crates" / "tools" / "src" / "webwright" / "evidence.rs"])
    verify(C3_1, [root / "crates" / "core" / "src" / "budget.rs"])
    # C3.2 spans the core connector and the production UI connector.
    verify(
        C3_2,
        [
            root / "crates" / "core" / "src" / "connector.rs",
            root / "crates" / "ui" / "src" / "liveview_connector" / "pick_connector.rs",
        ],
    )

    return ok


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=REPO_ROOT,
        help="repo root (defaults to the repo containing this script)",
    )
    args = parser.parse_args()

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
