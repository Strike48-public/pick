#!/usr/bin/env bash
# Create GitHub labels for Pick repository

set -euo pipefail

PICK_REPO="Strike48-public/pick"

echo "Creating labels in Pick repository ($PICK_REPO)..."
echo ""

# Type labels
echo "Creating type labels..."
gh label create "type: feature" --description "New feature or capability" --color "0E8A16" --repo "$PICK_REPO" || true
gh label create "type: enhancement" --description "Enhancement to existing feature" --color "1D76DB" --repo "$PICK_REPO" || true
gh label create "type: bug" --description "Bug or defect" --color "D73A4A" --repo "$PICK_REPO" || true
gh label create "type: refactor" --description "Code refactoring" --color "FBCA04" --repo "$PICK_REPO" || true
gh label create "type: docs" --description "Documentation changes" --color "0075CA" --repo "$PICK_REPO" || true
gh label create "type: test" --description "Test additions or updates" --color "BFD4F2" --repo "$PICK_REPO" || true
gh label create "type: chore" --description "Maintenance or tooling" --color "FEF2C0" --repo "$PICK_REPO" || true

# Priority labels
echo "Creating priority labels..."
gh label create "priority: P0" --description "Critical - Immediate attention" --color "B60205" --repo "$PICK_REPO" || true
gh label create "priority: P1" --description "High - Important" --color "D93F0B" --repo "$PICK_REPO" || true
gh label create "priority: P2" --description "Medium - Normal priority" --color "FBCA04" --repo "$PICK_REPO" || true
gh label create "priority: P3" --description "Low - Nice to have" --color "0E8A16" --repo "$PICK_REPO" || true
gh label create "priority: P4" --description "Backlog - Future consideration" --color "C2E0C6" --repo "$PICK_REPO" || true

# Feature area labels
echo "Creating feature labels..."
gh label create "feature: evidence-chains" --description "Evidence Chain Infrastructure" --color "0366D6" --repo "$PICK_REPO" || true
gh label create "feature: post-exploit" --description "Post-exploitation tools and UI" --color "FF6B6B" --repo "$PICK_REPO" || true
gh label create "feature: autopwn" --description "WiFi AutoPwn functionality" --color "4ECDC4" --repo "$PICK_REPO" || true
gh label create "feature: knowledge-graph" --description "Knowledge graph visualization" --color "45B7D1" --repo "$PICK_REPO" || true

# Size/Effort labels
echo "Creating size labels..."
gh label create "size: XS" --description "Extra small - < 1 day" --color "E4E669" --repo "$PICK_REPO" || true
gh label create "size: S" --description "Small - 1-2 days" --color "D4C5F9" --repo "$PICK_REPO" || true
gh label create "size: M" --description "Medium - 3-5 days" --color "C2E0C6" --repo "$PICK_REPO" || true
gh label create "size: L" --description "Large - 1-2 weeks" --color "F9D0C4" --repo "$PICK_REPO" || true
gh label create "size: XL" --description "Extra large - > 2 weeks" --color "D73A4A" --repo "$PICK_REPO" || true

# Status labels
echo "Creating status labels..."
gh label create "status: blocked" --description "Blocked by dependency" --color "D93F0B" --repo "$PICK_REPO" || true
gh label create "status: in-progress" --description "Currently being worked on" --color "0E8A16" --repo "$PICK_REPO" || true
gh label create "status: needs-review" --description "Ready for review" --color "FBCA04" --repo "$PICK_REPO" || true
gh label create "status: needs-testing" --description "Needs testing" --color "BFD4F2" --repo "$PICK_REPO" || true

echo ""
echo "Labels created successfully in $PICK_REPO!"
echo ""
echo "Label scheme:"
echo "- Type: feature, enhancement, bug, refactor, docs, test, chore"
echo "- Priority: P0 (critical), P1 (high), P2 (medium), P3 (low), P4 (backlog)"
echo "- Feature: evidence-chains, post-exploit, autopwn, knowledge-graph"
echo "- Milestone: week-1 through week-8"
echo "- Size: XS (<1d), S (1-2d), M (3-5d), L (1-2w), XL (>2w)"
echo "- Status: blocked, in-progress, needs-review, needs-testing"
