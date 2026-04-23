# Quick Action Modal Stalls and Prevents Tool Execution

## Summary
When clicking Quick Actions (AutoPwn, etc.) in the dashboard, the parameter modal appears but clicking the action button causes the UI to stall. The modal remains open indefinitely, and the tool never executes. Even after page refresh, the modal persists in the stuck state.

## Environment
- **Version:** feature/autopwn-quick-wins branch (commit 91990a2)
- **Mode:** Headless (`./run-pentest.sh headless dev`)
- **Server:** wss://jt-demo-01.strike48.engineering
- **Tenant:** non-prod
- **Browser:** Brave (Chromium-based)

## Steps to Reproduce
1. Launch Pick in headless mode
2. Navigate to Dashboard
3. Click "AutoPwn" in Quick Actions panel
4. Modal opens with pre-filled parameters
5. Click action button (Run/Execute/Submit) in modal
6. **Bug:** Modal stays open, nothing happens
7. Wait 30+ seconds - no change
8. Refresh page
9. **Bug persists:** Modal still shows "Awaiting approval..."

## Expected Behavior
1. Click action button in modal
2. Modal closes
3. Tool execution starts
4. Chat shows tool execution progress/results
5. Logs show: `[tool] autopwn_scan started`

## Actual Behavior
1. Click action button in modal
2. Modal remains open (stuck)
3. No visual feedback (no spinner, no error)
4. Tool never executes (no logs)
5. Page refresh shows "Awaiting approval..." in modal
6. Modal state persists indefinitely

## Logs During Incident

**Pick logs show NO tool execution:**
```
2026-04-08 18:14:51 [OK] [chat] loaded 10 agents
2026-04-08 18:15:04 [INFO] [shell] initializing (mode=native)
2026-04-08 18:15:04 [OK] [shell] terminal connected
2026-04-08 18:15:06 [OK] [chat] loaded 10 agents

# User clicks AutoPwn Quick Action at ~18:15
# ... NO TOOL LOGS HERE ...

2026-04-08 18:18:07 [INFO] Reconnecting with JWT authentication...
2026-04-08 18:18:08 [OK] Registered with Strike48
# (continues with 4-minute reconnection pattern)
```

**Key observation:** No `[tool] autopwn_scan started` or any tool execution logs.

## Screenshots

**Before refresh (modal stuck):**
![Screenshot from 2026-04-08 14-36-28](https://github.com/user-attachments/assets/...)

**After refresh (still stuck):**
![Screenshot from 2026-04-08 14-37-15](https://github.com/user-attachments/assets/...)

## Additional Context

### Hypotheses for Root Cause

1. **Event Handler Not Firing**
   - Button click not triggering action handler
   - JavaScript error preventing execution

2. **Permission System Blocking**
   - "Awaiting approval" suggests permission system involved
   - Tool execution queued but approval modal never shown
   - Permission prompt hidden/suppressed

3. **State Persistence Bug**
   - Modal state persisted to localStorage
   - On refresh, stale state loaded
   - Actual tool execution never initiated

4. **WebSocket/Connection Issue**
   - Tool execution request fails to send
   - Connection drops during request
   - No retry mechanism

### Browser Console Investigation
**Console (F12):** No JavaScript errors or warnings
**Network Tab:** No failed requests, no pending requests
**Result:** Silent failure - no error messages anywhere

### Workaround
**None found.** Modal persists even after:
- Page refresh
- Waiting extended time
- Closing and reopening Pick
- Clearing browser cache and localStorage
- Opening in new tab

**The modal state appears to be persisted server-side or in session storage that survives cache clearing.**

### Impact
**Severity: High**
- Quick Actions completely broken
- No way to execute tools via Quick Actions
- Blocks autonomous pentesting workflows
- Users must fall back to manual chat commands

## Suggested Investigation Areas

1. **Check Quick Action event handlers:**
   - `crates/ui/src/components/dashboard.rs`
   - Modal button click handlers
   - Tool execution trigger logic

2. **Check permission system:**
   - Are Quick Actions requesting permission?
   - Is permission UI being shown?
   - Permission state management

3. **Check modal state management:**
   - Where is modal state stored?
   - Is it persisted to localStorage?
   - State cleanup on tool execution

4. **Check tool execution flow:**
   - How do Quick Actions invoke tools?
   - Are they using the same path as chat commands?
   - Error handling in tool invocation

## Related Code Locations

- Quick Actions: `crates/ui/src/components/dashboard.rs`
- Tool execution: `crates/core/src/connector.rs`
- Permission system: [TBD - need to locate]
- Modal components: [TBD - need to locate]

## Reproduction Rate
**100%** - Occurs every time a Quick Action is clicked.

---

**Labels:** bug, high-priority, ui, quick-actions, tool-execution
**Milestone:** v0.2.0 (or next release)
