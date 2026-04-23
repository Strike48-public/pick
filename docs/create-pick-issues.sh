#!/usr/bin/env bash
# Create Pick-specific GitHub issues for 60-day MVP

set -euo pipefail

# Use the public Pick repository (Strike48-public/pick) which has issues enabled
# Note: jtomek-strike48/pick has issues disabled
PICK_REPO="Strike48-public/pick"

echo "Using repository: $PICK_REPO"
echo ""

echo "Creating Pick-specific issues in Pick repository..."
echo ""

# First, create the new feature labels
echo "Creating additional feature labels for Pick..."
gh label create "feature: post-exploit" --description "Post-exploitation tools and UI" --color "FF6B6B" --repo "$PICK_REPO" || true
gh label create "feature: autopwn" --description "WiFi AutoPwn functionality" --color "4ECDC4" --repo "$PICK_REPO" || true
gh label create "feature: knowledge-graph" --description "Knowledge graph visualization" --color "45B7D1" --repo "$PICK_REPO" || true
gh label create "feature: evidence-chains" --description "Evidence Chain Infrastructure" --color "0366D6" --repo "$PICK_REPO" || true

echo ""
echo "Creating Pick issues..."

# Issue P1: Post-Exploitation Tool UI Enhancements
gh issue create --repo "$PICK_REPO" --title "Post-Exploitation Tool UI Enhancements" --body "$(cat <<'EOF'
**Description:**

Enhance UI for post-exploitation tools (credential harvest, lateral movement) to improve usability and visibility of results.

**Acceptance Criteria:**

- [ ] Credential harvest results displayed in organized table/list
- [ ] Lateral movement options clearly presented with success indicators
- [ ] Real-time progress updates during execution
- [ ] Export functionality for credentials and findings
- [ ] Error handling with clear user messages
- [ ] Results persist across sessions

**Technical Approach:**

Enhance UI components for post-exploitation tools:

```rust
// Update credential harvest display
// crates/ui/src/components/post_exploit/credential_display.rs

pub fn CredentialDisplay(cx: Scope<CredentialDisplayProps>) -> Element {
    // Group by type: WiFi passwords, SSH keys, env secrets, config files
    // Display in categorized tables with copy-to-clipboard
    // Add export button (JSON/CSV)
}

// Update lateral movement UI
// crates/ui/src/components/post_exploit/lateral_movement.rs

pub fn LateralMovementPanel(cx: Scope) -> Element {
    // Show available techniques with descriptions
    // Real-time status for each attempt
    // Success/failure indicators with details
}
```

**Files to Create:**

- `crates/ui/src/components/post_exploit/credential_display.rs`
- `crates/ui/src/components/post_exploit/lateral_movement.rs`
- `crates/ui/src/components/post_exploit/mod.rs`

**Files to Modify:**

- `crates/ui/src/components/dashboard.rs` (integrate post-exploit panels)
- `crates/ui/src/components/mod.rs`

**Testing:**

- UI component tests for credential display
- Test export functionality (JSON/CSV formats)
- Test real-time updates during execution
- Integration test: credential harvest → display → export
EOF
)" --label "type: enhancement,priority: P1,feature: post-exploit,size: L"

echo "Issue P1 created"

# Issue P2: Polish WiFi AutoPwn UI/UX
gh issue create --repo "$PICK_REPO" --title "Polish WiFi AutoPwn UI/UX" --body "$(cat <<'EOF'
**Description:**

Polish existing WiFi AutoPwn UI for better user experience and clarity.

**Acceptance Criteria:**

- [ ] Clear status indicators for each AutoPwn phase
- [ ] Progress bars for long-running operations
- [ ] Better error messages with actionable suggestions
- [ ] Network scan results displayed in sortable table
- [ ] Success/failure visual feedback
- [ ] "Stop" button to cancel AutoPwn mid-execution

**Technical Approach:**

UI improvements:

```rust
// Add phase indicators
enum AutoPwnPhase {
    AdapterCheck,
    NetworkScan,
    HandshakeCapture,
    PasswordCrack,
    PostExploit,
}

// Progress tracking
struct AutoPwnProgress {
    current_phase: AutoPwnPhase,
    phase_progress: f32,  // 0.0 to 1.0
    status_message: String,
    can_cancel: bool,
}

// Enhanced network display
// Sort by signal strength, security type, channel
// Color-code by security level
```

**Files to Modify:**

- `crates/ui/src/components/autopwn_panel.rs`
- `crates/ui/src/components/dashboard.rs`
- `crates/ui/src/components/chat_panel/next_steps.rs`

**Testing:**

- UI component tests for phase indicators
- Test cancel functionality
- Test error message clarity
- User testing: can non-technical users understand the flow?
EOF
)" --label "type: enhancement,priority: P2,feature: autopwn,size: M"

echo "Issue P2 created"

# Issue P3: Integrate StrikeKit Evidence Chain APIs
gh issue create --repo "$PICK_REPO" --title "Integrate StrikeKit Evidence Chain APIs" --body "$(cat <<'EOF'
**Description:**

Update Pick to send evidence data to StrikeKit and create evidence chains for all findings.

**Acceptance Criteria:**

- [ ] Pick sends evidence to StrikeKit for each tool execution
- [ ] Evidence includes: tool name, raw output, structured data, confidence score
- [ ] Hypotheses generated from AI interpretations
- [ ] Exploit attempts linked to hypotheses
- [ ] Findings linked to exploit attempts
- [ ] Error handling for StrikeKit API failures

**Technical Approach:**

Integrate with StrikeKit evidence chain APIs:

```rust
// Add evidence tracking to tool execution
// crates/core/src/tool_executor.rs

impl ToolExecutor {
    async fn execute_with_evidence(&self, tool: &Tool) -> Result<ExecutionResult> {
        // Execute tool
        let result = self.execute(tool).await?;

        // Send evidence to StrikeKit
        let evidence = Evidence {
            source_tool: tool.name.clone(),
            source_execution_id: result.execution_id.clone(),
            evidence_type: result.evidence_type.clone(),
            target: result.target.clone(),
            raw_data: result.raw_output.clone(),
            structured_data: result.structured_output,
            confidence: result.confidence,
            timestamp: Utc::now(),
        };

        self.strikekit_client.create_evidence(evidence).await?;

        Ok(result)
    }
}
```

**Files to Create:**

- `crates/core/src/evidence_client.rs` (StrikeKit API client)

**Files to Modify:**

- `crates/core/src/tool_executor.rs`
- `crates/tools/src/lib.rs` (add evidence metadata to tool results)

**Testing:**

- Unit tests for evidence creation
- Integration test: tool execution → evidence sent → StrikeKit receives
- Test failure handling: StrikeKit unavailable
EOF
)" --label "type: feature,priority: P2,feature: evidence-chains,size: L"

echo "Issue P3 created"

# Issue P4: Display Knowledge Graph from StrikeKit
gh issue create --repo "$PICK_REPO" --title "Display Knowledge Graph from StrikeKit" --body "$(cat <<'EOF'
**Description:**

Add knowledge graph visualization to Pick UI showing evidence chains from StrikeKit.

**Acceptance Criteria:**

- [ ] Fetch evidence chains from StrikeKit API
- [ ] Display graph using JavaScript library (Cytoscape.js)
- [ ] Show nodes: Evidence, Hypothesis, Exploit Attempt, Finding
- [ ] Show edges: causal relationships
- [ ] Color-code by confidence level
- [ ] Click node to show details
- [ ] Filter by engagement/target

**Technical Approach:**

Embed JavaScript graph library in Dioxus:

```rust
// crates/ui/src/components/knowledge_graph.rs

pub fn KnowledgeGraph(cx: Scope<KnowledgeGraphProps>) -> Element {
    let engagement_id = use_state(cx, || cx.props.engagement_id.clone());
    let graph_data = use_future(cx, engagement_id, |id| async move {
        fetch_evidence_chain(id).await
    });

    render! {
        div {
            class: "knowledge-graph-container",
            // Embed Cytoscape.js via script tag or web component
            script { src: "https://unpkg.com/cytoscape/dist/cytoscape.min.js" }
            div {
                id: "cy",
                style: "width: 100%; height: 600px;",
                // Initialize graph with data
            }
        }
    }
}
```

**Files to Create:**

- `crates/ui/src/components/knowledge_graph.rs`
- `static/js/graph-init.js` (Cytoscape initialization)

**Files to Modify:**

- `crates/ui/src/components/dashboard.rs` (add graph tab)
- `crates/core/src/evidence_client.rs` (add fetch_evidence_chain method)

**Testing:**

- Component test: graph renders with sample data
- Test graph interactivity (zoom, pan, click)
- Test filtering by engagement/target
- Performance test: graph with 100+ nodes
EOF
)" --label "type: feature,priority: P2,feature: knowledge-graph,size: L"

echo "Issue P4 created"

echo ""
echo "Pick issues created successfully!"
echo ""
echo "Summary:"
echo "- Issue P1: Post-Exploitation Tool UI Enhancements (P1, week-3)"
echo "- Issue P2: Polish WiFi AutoPwn UI/UX (P2, week-4)"
echo "- Issue P3: Integrate StrikeKit Evidence Chain APIs (P2, week-5)"
echo "- Issue P4: Display Knowledge Graph from StrikeKit (P2, week-6)"
echo ""
echo "Total: 4 Pick-specific issues"
