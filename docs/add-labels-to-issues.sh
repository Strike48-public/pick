#!/usr/bin/env bash
# Add proper labels to all GitHub issues in StrikeKit repository
# Run this AFTER creating all issues with create-all-issues.sh

set -euo pipefail

cd /home/jtomek/Code/strikekit

echo "Adding labels to all issues..."
echo ""

# Get the starting issue number (assumes issues were created sequentially)
# You may need to adjust these numbers based on actual issue numbers
ISSUE_A1=94  # Already created
ISSUE_A2=95
ISSUE_A3=96
ISSUE_A4=97
ISSUE_A5=98
ISSUE_B1=99
ISSUE_B2=100
ISSUE_B3=101
ISSUE_B4=102
ISSUE_C1=103
ISSUE_C2=104
ISSUE_C3=105
ISSUE_C4=106
ISSUE_D1=107
ISSUE_D2=108
ISSUE_D3=109
ISSUE_D4=110
ISSUE_X1=111
ISSUE_X2=112
ISSUE_X3=113

echo "Team A: Evidence Chain Infrastructure"
gh issue edit $ISSUE_A1 --add-label "type: feature,priority: P1,feature: evidence-chains,milestone: week-1,size: M" || echo "Failed to update issue $ISSUE_A1"
gh issue edit $ISSUE_A2 --add-label "type: feature,priority: P1,feature: evidence-chains,milestone: week-2,size: L" || echo "Failed to update issue $ISSUE_A2"
gh issue edit $ISSUE_A3 --add-label "type: feature,priority: P1,feature: evidence-chains,milestone: week-3,size: L" || echo "Failed to update issue $ISSUE_A3"
gh issue edit $ISSUE_A4 --add-label "type: feature,priority: P1,feature: evidence-chains,milestone: week-4,size: L" || echo "Failed to update issue $ISSUE_A4"
gh issue edit $ISSUE_A5 --add-label "type: enhancement,priority: P2,feature: evidence-chains,milestone: week-5,size: L" || echo "Failed to update issue $ISSUE_A5"

echo "Team B: RAG Knowledge Base"
gh issue edit $ISSUE_B1 --add-label "type: feature,priority: P1,feature: rag,milestone: week-1,size: L" || echo "Failed to update issue $ISSUE_B1"
gh issue edit $ISSUE_B2 --add-label "type: feature,priority: P1,feature: rag,milestone: week-2,size: M" || echo "Failed to update issue $ISSUE_B2"
gh issue edit $ISSUE_B3 --add-label "type: feature,priority: P1,feature: rag,milestone: week-3,size: L" || echo "Failed to update issue $ISSUE_B3"
gh issue edit $ISSUE_B4 --add-label "type: enhancement,priority: P2,feature: rag,milestone: week-4,size: L" || echo "Failed to update issue $ISSUE_B4"

echo "Team C: AI Planning & Reflector"
gh issue edit $ISSUE_C1 --add-label "type: feature,priority: P1,feature: ai-planning,milestone: week-1,size: L" || echo "Failed to update issue $ISSUE_C1"
gh issue edit $ISSUE_C2 --add-label "type: feature,priority: P1,feature: ai-planning,milestone: week-3,size: XL" || echo "Failed to update issue $ISSUE_C2"
gh issue edit $ISSUE_C3 --add-label "type: feature,priority: P1,feature: ai-planning,milestone: week-4,size: L" || echo "Failed to update issue $ISSUE_C3"
gh issue edit $ISSUE_C4 --add-label "type: feature,priority: P2,feature: ai-planning,milestone: week-3,size: M" || echo "Failed to update issue $ISSUE_C4"

echo "Team D: Integrations & Polish"
gh issue edit $ISSUE_D1 --add-label "type: feature,priority: P2,feature: integrations,milestone: week-1,size: M" || echo "Failed to update issue $ISSUE_D1"
gh issue edit $ISSUE_D2 --add-label "type: feature,priority: P2,feature: integrations,milestone: week-2,size: M" || echo "Failed to update issue $ISSUE_D2"
gh issue edit $ISSUE_D3 --add-label "type: feature,priority: P2,feature: integrations,milestone: week-3,size: L" || echo "Failed to update issue $ISSUE_D3"
gh issue edit $ISSUE_D4 --add-label "type: feature,priority: P1,feature: integrations,milestone: week-5,size: L" || echo "Failed to update issue $ISSUE_D4"

echo "Cross-Team Issues"
gh issue edit $ISSUE_X1 --add-label "type: test,priority: P1,milestone: week-6,size: L" || echo "Failed to update issue $ISSUE_X1"
gh issue edit $ISSUE_X2 --add-label "type: docs,priority: P2,milestone: week-7,size: L" || echo "Failed to update issue $ISSUE_X2"
gh issue edit $ISSUE_X3 --add-label "type: chore,priority: P1,milestone: week-8,size: L" || echo "Failed to update issue $ISSUE_X3"

echo ""
echo "Labels added successfully!"
echo ""
echo "NOTE: If issue numbers don't match, edit this script and update the variables at the top."
echo "You can check issue numbers with: gh issue list"
