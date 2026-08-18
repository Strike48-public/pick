#!/usr/bin/env bash
# install-hooks.sh - Wire the versioned .githooks/ directory into this repo.
#
# Run once after cloning. This points git at the tracked hooks in .githooks/
# so pre-commit and commit-msg PII checks run automatically.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "Installing git hooks from .githooks/ ..."
git config core.hooksPath .githooks
chmod +x .githooks/* scripts/check-pii.sh

# Seed the local (gitignored) PII name list from the example if it's missing,
# so the PII hooks have a list to scan against. The scanner fails loud without
# one; edit .pii-names.local to add the real customer/tenant names.
if [[ ! -f .pii-names.local && -f .pii-names.local.example ]]; then
    cp .pii-names.local.example .pii-names.local
    echo "Created .pii-names.local from the example - edit it to add the real names."
fi

echo ""
echo "Hooks installed. The following hooks will run on every commit:"
echo "  - pre-commit: scans staged changes for customer names (PII)"
echo "  - commit-msg: scans commit messages for customer names (PII)"

# Make the placeholder-only state obvious: if the local list is still identical
# to the committed example, the hooks scan against placeholder names only and
# provide no real protection until an operator fills in the real list. The real
# names are secret and distributed out-of-band, so CI (with the PII_NAMES
# secret) remains the authoritative gate - see scripts/check-pii.sh.
if [[ -f .pii-names.local && -f .pii-names.local.example ]] \
    && cmp -s .pii-names.local .pii-names.local.example; then
    echo ""
    echo "WARNING: .pii-names.local still contains only the placeholder example names."
    echo "         The local hooks scan against placeholders and will NOT catch real"
    echo "         customer names until you edit .pii-names.local with the real list."
fi

echo ""
echo "To disable: git config --unset core.hooksPath"
