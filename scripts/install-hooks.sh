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

echo ""
echo "Hooks installed. The following hooks will run on every commit:"
echo "  - pre-commit: scans staged changes for customer names (PII)"
echo "  - commit-msg: scans commit messages for customer names (PII)"
echo ""
echo "To disable: git config --unset core.hooksPath"
