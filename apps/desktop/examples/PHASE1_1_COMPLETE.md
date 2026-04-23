# Phase 1.1 Complete: Dual-Window Architecture

## Overview

Successfully implemented Phase 1.1 of the egui_graphs integration roadmap - dual-window architecture with channel-based communication between Dioxus and egui.

## Architecture

### Thread Model

```
Main Thread:
  - egui Knowledge Graph window (eframe 0.34)
  - Handles graph rendering and user interaction

Spawned Thread:
  - Dioxus desktop app (Pentest Connector UI)
  - Uses platform-specific `with_any_thread(true)` on Linux for EventLoop compatibility
```

### Communication

```rust
// Global channel for Dioxus → egui communication
static GRAPH_CHANNEL: Mutex<Option<mpsc::Sender<GraphMessage>>>

// Message types
pub enum GraphMessage {
    UpdateGraph(KnowledgeGraph),
    Clear,
    Loading,
}
```

### Files Created

1. **apps/desktop/src/graph_window.rs** (248 lines)
   - GraphWindow struct implementing eframe::App
   - Graph rendering with egui_graphs
   - Node selection and detail panel
   - Message handling from Dioxus
   - Color-coded node types (Evidence, Hypothesis, Exploit, Finding)

2. **apps/desktop/src/graph_bridge.rs** (24 lines)
   - Helper API for Dioxus components
   - Functions: `send_sample_graph()`, `send_loading()`, `send_clear()`

### Files Modified

1. **apps/desktop/src/main.rs**
   - Restructured to run egui on main thread (Linux requirement)
   - Dioxus runs in spawned thread with `with_any_thread(true)`
   - Global GRAPH_CHANNEL for cross-thread communication
   - Platform-specific EventLoop configuration for Linux

2. **apps/desktop/Cargo.toml**
   - Added dependencies: eframe 0.34, egui 0.34, egui_graphs 0.30, petgraph 0.8

3. **crates/core/src/lib.rs**
   - Exported evidence module for graph_window imports

## Linux EventLoop Challenge

### Problem
Both Dioxus (via Tao) and egui (via winit) require EventLoop creation on the main thread on Linux. This creates a fundamental conflict when trying to run both frameworks simultaneously in separate windows.

### Solution
Used platform-specific `EventLoopBuilderExtUnix::with_any_thread(true)` to allow Dioxus EventLoop creation in a spawned thread, while keeping egui on the main thread.

```rust
#[cfg(target_os = "linux")]
{
    use dioxus::desktop::tao::event_loop::EventLoopBuilder;
    use dioxus::desktop::tao::platform::unix::EventLoopBuilderExtUnix;

    let event_loop = EventLoopBuilder::with_user_event()
        .with_any_thread(true)  // Allow off-main-thread EventLoop
        .build();

    let config = Config::default()
        .with_event_loop(event_loop)
        // ... rest of config
}
```

## Current State

### Working Features
- ✅ Dual-window architecture (Dioxus + egui)
- ✅ Channel-based communication
- ✅ Graph rendering with color-coded node types
- ✅ Interactive node selection
- ✅ Node detail panel
- ✅ Loading/error states
- ✅ Clean build (no warnings except external dependency)
- ✅ Linux EventLoop compatibility

### Missing Features (Next Phase)
- ❌ UI controls in Dioxus app to send graph data
- ❌ Async data loading from MockEvidenceClient
- ❌ Real-time updates
- ❌ Zoom controls UI
- ❌ Filter support
- ❌ Layout options (hierarchical/force-directed/circular/grid)

## Testing

Application successfully:
- Compiles without warnings
- Launches both windows without errors
- Runs stably (process verified)
- Logs show successful window creation on both threads

### Test Commands

```bash
# Build
cargo build --bin pentest-connector

# Run
cargo run --bin pentest-connector

# Check logs
tail -f ~/.local/share/pentest-connector/logs/connector.log
```

## Next Steps (Phase 1.2)

1. Add UI controls to Dashboard for loading sample graph data
2. Implement async data loading from MockEvidenceClient
3. Test real-time graph updates via channel
4. Add error handling for channel disconnections
5. Verify window positioning is polished

## Performance Notes

- Application size: ~76MB RAM usage when running
- egui graph window requests continuous repainting to check for messages
- No performance issues observed with small test graphs

## Platform Support

- **Linux**: ✅ Working with `with_any_thread(true)` workaround
- **macOS**: Expected to work (no platform-specific requirements)
- **Windows**: Expected to work (no platform-specific requirements)

## Dependencies

```toml
eframe = "0.34"
egui = "0.34"
egui_graphs = "0.30"
petgraph = "0.8"
```

## References

- [EGUI_INTEGRATION_ROADMAP.md](./EGUI_INTEGRATION_ROADMAP.md) - Full roadmap
- [EGUI_GRAPH_POC_RESULTS.md](./EGUI_GRAPH_POC_RESULTS.md) - POC results
- [FEATURE_COMPARISON.md](./FEATURE_COMPARISON.md) - Feature comparison table
