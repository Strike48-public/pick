#!/usr/bin/env bash
# Create GitHub labels for 60-day MVP in StrikeKit repository

set -euo pipefail

cd /home/jtomek/Code/strikekit

echo "Creating labels in StrikeKit repository..."
echo ""

# Type labels (feat/bug/enhancement/etc.)
echo "Creating type labels..."
gh label create "type: feature" --description "New feature or capability" --color "0E8A16" || true
gh label create "type: enhancement" --description "Enhancement to existing feature" --color "1D76DB" || true
gh label create "type: bug" --description "Bug or defect" --color "D73A4A" || true
gh label create "type: refactor" --description "Code refactoring" --color "FBCA04" || true
gh label create "type: docs" --description "Documentation changes" --color "0075CA" || true
gh label create "type: test" --description "Test additions or updates" --color "BFD4F2" || true
gh label create "type: chore" --description "Maintenance or tooling" --color "FEF2C0" || true

# Priority labels (P0-P4)
echo "Creating priority labels..."
gh label create "priority: P0" --description "Critical - Immediate attention" --color "B60205" || true
gh label create "priority: P1" --description "High - Important" --color "D93F0B" || true
gh label create "priority: P2" --description "Medium - Normal priority" --color "FBCA04" || true
gh label create "priority: P3" --description "Low - Nice to have" --color "0E8A16" || true
gh label create "priority: P4" --description "Backlog - Future consideration" --color "C2E0C6" || true

# Feature area labels
echo "Creating feature labels..."
gh label create "feature: evidence-chains" --description "Evidence Chain Infrastructure" --color "0366D6" || true
gh label create "feature: rag" --description "RAG Knowledge Base" --color "5319E7" || true
gh label create "feature: ai-planning" --description "AI Planning & Reflector" --color "D876E3" || true
gh label create "feature: integrations" --description "Integrations & Polish" --color "C5DEF5" || true

# Size/Effort labels
echo "Creating size labels..."
gh label create "size: XS" --description "Extra small - < 1 day" --color "E4E669" || true
gh label create "size: S" --description "Small - 1-2 days" --color "D4C5F9" || true
gh label create "size: M" --description "Medium - 3-5 days" --color "C2E0C6" || true
gh label create "size: L" --description "Large - 1-2 weeks" --color "F9D0C4" || true
gh label create "size: XL" --description "Extra large - > 2 weeks" --color "D73A4A" || true

# Status labels
echo "Creating status labels..."
gh label create "status: blocked" --description "Blocked by dependency" --color "D93F0B" || true
gh label create "status: in-progress" --description "Currently being worked on" --color "0E8A16" || true
gh label create "status: needs-review" --description "Ready for review" --color "FBCA04" || true
gh label create "status: needs-testing" --description "Needs testing" --color "BFD4F2" || true

echo ""
echo "Labels created successfully!"
echo ""
echo "Label scheme:"
echo "- Type: feature, enhancement, bug, refactor, docs, test, chore"
echo "- Priority: P0 (critical), P1 (high), P2 (medium), P3 (low), P4 (backlog)"
echo "- Feature: evidence-chains, rag, ai-planning, integrations"
echo "- Size: XS (<1d), S (1-2d), M (3-5d), L (1-2w), XL (>2w)"
echo "- Status: blocked, in-progress, needs-review, needs-testing"
echo ""
echo "Example: Add labels to issue #94:"
  gh issue edit 94 --add-label 'type: feature,priority: P1,feature: evidence-chains,size: M'
