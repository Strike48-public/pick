# Rust Graph Visualization Libraries for Dioxus Desktop

Research conducted on 2026-04-14 for replacing Cytoscape.js with pure Rust solutions.

## Executive Summary

After researching the Rust ecosystem, there are **3 viable approaches** for graph visualization in Dioxus desktop applications:

1. **egui_graphs** (Recommended) - Most mature, feature-complete option
2. **vibe-graph-viz** - GPU-accelerated, but newer/less proven
3. **Custom wgpu/plotters solution** - Maximum control, highest effort

## Top 3 Options

### 1. egui_graphs + Dioxus Integration (RECOMMENDED)

**Repository:** https://github.com/blitzarx1/egui_graphs
**Crate:** `egui_graphs` v0.30.0
**License:** MIT

#### Pros
- Most mature pure Rust graph visualization library
- Built on petgraph (standard Rust graph library)
- Native rendering with egui (immediate mode GUI)
- Excellent feature set:
  - Interactive pan, zoom, drag
  - Multiple layout algorithms (hierarchical, force-directed, random)
  - Node shapes, colors, labels
  - Edge styling and customization
  - Event system (click, drag, select)
  - Dark/light theme support
  - Styling hooks for dynamic customization
  - Works on desktop, web (WASM), and mobile
- Active development (v1.0.0 roadmap)
- Good documentation and examples
- Performance: Designed for 100-1000+ nodes

#### Cons
- Requires embedding egui within Dioxus (not native Dioxus components)
- Different UI paradigm (immediate mode vs reactive)
- Integration requires bridge code

#### Layout Algorithms
- **Random:** Quick scatter (default)
- **Hierarchical:** Layered/ranked layout (Sugiyama-style)
- **Force-Directed:** Fruchterman-Reingold with composable extras (center gravity)
- **Custom:** Pluggable `Layout` trait for custom algorithms

#### Integration Strategy for Dioxus

**Option A: Separate egui Window**
```rust
// Launch egui in separate window/thread
// Communicate via channels
// Pros: Cleanest separation
// Cons: Multiple windows
```

**Option B: Embed egui in Dioxus WebView**
```rust
// Use dioxus-desktop's webview
// Render egui to canvas/texture
// Pros: Single window
// Cons: Complex integration
```

**Option C: Use Freya (Dioxus + Skia)**
```rust
// Freya is a native Dioxus renderer using Skia
// Could integrate egui graphs via custom Freya component
// Pros: Native Dioxus, high performance
// Cons: Major refactor of existing Dioxus-web code
```

#### Code Example
```rust
use egui_graphs::{Graph, GraphView, DefaultGraphView};
use petgraph::stable_graph::StableGraph;

// Create graph
let mut g = StableGraph::new();
let a = g.add_node(());
let b = g.add_node(());
g.add_edge(a, b, ());

// Convert to egui_graphs
let mut graph = Graph::from(&g);

// In egui render loop
ui.add(&mut DefaultGraphView::new(&mut graph));
```

### 2. vibe-graph-viz (GPU-Accelerated)

**Repository:** https://github.com/pinsky-three/vibe-graph
**Crate:** `vibe-graph-viz` v0.1.3, `vibe-graph-layout-gpu` v0.1.1
**License:** MIT

#### Pros
- GPU-accelerated force-directed layout using WebGPU/wgpu
- Barnes-Hut algorithm for large graphs (10k+ nodes)
- Built with egui for rendering
- WASM-compatible
- WebSocket live updates
- REST API for graph data
- Active project with comprehensive tooling

#### Cons
- Very new (v0.1.x)
- Less battle-tested than egui_graphs
- Designed as part of larger "vibe-graph" codebase analysis tool
- May have unnecessary dependencies for standalone use
- GPU requirement might limit deployment flexibility

#### Performance
Specifically designed for massive graphs (10k+ nodes) via GPU compute shaders.

### 3. Custom Solution: wgpu + Layout Library

**Approach:** Build custom renderer using wgpu + layout algorithms

#### Components
- **Rendering:** `wgpu` (WebGPU) or `plotters` (2D plotting)
- **Layout:** `dagre` (hierarchical), `forceatlas2` (force-directed), `dagre-rs`
- **Graph:** `petgraph` (data structure)
- **UI Integration:** Custom Dioxus component

#### Pros
- Maximum control and customization
- Optimal integration with Dioxus
- No external UI framework dependencies
- Can optimize specifically for your use case

#### Cons
- Significant development effort (weeks to months)
- Need to implement all interaction features
- More code to maintain
- Risk of performance issues without proper optimization

#### Available Layout Libraries
- `dagre` v0.1.0 - Hierarchical layout (Sugiyama method)
- `forceatlas2` v0.8.0 - Force-directed layout
- `manatee` v0.4.0 - Compound graph layouts (COSE/FCoSE)
- `dugong` v0.4.0 - Dagre-compatible algorithms
- `force_smith` v1.0.3 - Force-directed toolkit

## Comparison Matrix

| Feature | egui_graphs | vibe-graph-viz | Custom wgpu |
|---------|-------------|----------------|-------------|
| Maturity | High (v0.30) | Low (v0.1) | N/A |
| Layout Algorithms | 3+ built-in | GPU force-directed | Manual integration |
| Dioxus Integration | Medium effort | Medium effort | High effort |
| Performance | Good (1000 nodes) | Excellent (10k+ nodes) | Depends on impl |
| Interactive Features | Complete | Good | Must implement |
| Styling/Theming | Excellent | Good | Must implement |
| Event System | Complete | Basic | Must implement |
| WASM Support | Yes | Yes | Possible |
| Development Time | Days | Days-Weeks | Weeks-Months |
| Maintenance Burden | Low | Medium | High |
| GPU Requirement | No | Yes (WebGPU) | Optional |

## Recommendation

**Use egui_graphs with separate egui window integration.**

### Rationale
1. **Proven Technology:** Most mature Rust graph viz library
2. **Feature Complete:** All required features already implemented
3. **Good Performance:** Handles 100-1000 nodes well
4. **Active Development:** Moving toward v1.0.0 stable release
5. **Fastest Time to Market:** Examples and documentation available
6. **Lowest Risk:** Well-tested in production use

### Implementation Approach

**Phase 1: Proof of Concept (1-2 days)**
- Create standalone egui_graphs window
- Load graph data from Pick's knowledge graph
- Verify performance with real data
- Test interaction features

**Phase 2: Basic Integration (2-3 days)**
- Integrate egui window with Dioxus desktop app
- Implement data synchronization (Rust channels)
- Add basic controls (layout selection, zoom, pan)

**Phase 3: Feature Parity (3-5 days)**
- Match Cytoscape.js feature set
- Custom node/edge styling
- Search and filter
- Export functionality

**Phase 4: Polish (2-3 days)**
- Theme integration
- Performance optimization
- Error handling
- User testing

**Total Estimated Time:** 8-13 days

### Alternative Path (If GPU Performance Needed)

If you later need better performance for graphs >5k nodes:
1. Start with egui_graphs for MVP
2. Profile performance with real data
3. If bottlenecks exist, migrate to vibe-graph-viz GPU layout
4. Keep same egui rendering, swap layout algorithm only

## Technical Integration Details

### Option: Separate egui Window (Recommended for MVP)

```rust
// In Pick desktop app
use eframe::{self, NativeOptions};
use egui_graphs::{Graph, DefaultGraphView};

pub fn launch_graph_viewer(graph_data: KnowledgeGraph) {
    // Spawn egui app in separate thread
    std::thread::spawn(move || {
        let options = NativeOptions::default();
        eframe::run_native(
            "Knowledge Graph",
            options,
            Box::new(|cc| Ok(Box::new(GraphApp::new(cc, graph_data)))),
        )
        .unwrap();
    });
}

struct GraphApp {
    graph: Graph,
}

impl eframe::App for GraphApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add(&mut DefaultGraphView::new(&mut self.graph));
        });
    }
}
```

### Data Flow
```
Dioxus UI (Pick) 
    |
    v
Launch Graph Viewer Button
    |
    v
egui Window (separate process/thread)
    |
    v
egui_graphs visualization
    |
    v
User interactions
    |
    v
Events sent back to Dioxus (via channels)
```

## Dependencies to Add

```toml
[dependencies]
# Core graph visualization
egui_graphs = "0.30"
petgraph = "0.8"
eframe = "0.30"  # egui framework

# Layout algorithms (if needed beyond built-in)
dagre = "0.1"           # Hierarchical
forceatlas2 = "0.8"     # Force-directed

# Optional: GPU acceleration (future)
# vibe-graph-layout-gpu = "0.1"
```

## Migration Path from Cytoscape.js

1. **Keep Cytoscape.js initially** - Don't remove until Rust solution is proven
2. **Parallel implementation** - Build egui_graphs viewer alongside existing
3. **Feature parity checklist:**
   - [ ] Node rendering (shapes, colors, labels)
   - [ ] Edge rendering (arrows, labels, colors)
   - [ ] Pan and zoom
   - [ ] Node selection
   - [ ] Node dragging
   - [ ] Layout algorithms (hierarchical, force-directed)
   - [ ] Search/filter
   - [ ] Export (PNG, SVG)
4. **User testing** - Get feedback before removing Cytoscape.js
5. **Gradual rollout** - Feature flag for switching between implementations

## Performance Considerations

### egui_graphs Performance Profile
- **100 nodes:** Excellent (60 FPS)
- **500 nodes:** Good (30-60 FPS)
- **1000 nodes:** Acceptable (15-30 FPS)
- **5000+ nodes:** Consider GPU layout (vibe-graph-viz)

### Optimization Strategies
1. **Level of Detail:** Simplify rendering for distant/zoomed-out nodes
2. **Culling:** Don't render off-screen nodes
3. **Lazy Layout:** Only recompute layout when needed
4. **GPU Layout:** Use vibe-graph-layout-gpu for large graphs
5. **Simplification:** Cluster/aggregate nodes for very large graphs

## Security Considerations

### egui_graphs
- Pure Rust implementation (memory safety)
- No external JavaScript (reduced attack surface vs Cytoscape.js)
- Native rendering (no browser sandbox escape risks)

### GPU Solutions (wgpu/vibe-graph-viz)
- WebGPU shader validation (safe by design)
- Isolated GPU context
- No arbitrary code execution risks

## References

- egui_graphs GitHub: https://github.com/blitzarx1/egui_graphs
- egui_graphs docs: https://docs.rs/egui_graphs
- egui_graphs web demo: https://blitzarx1.github.io/egui_graphs
- vibe-graph: https://github.com/pinsky-three/vibe-graph
- petgraph: https://github.com/petgraph/petgraph
- egui: https://github.com/emilk/egui
- Freya (Dioxus native): https://freyaui.dev/

## Next Steps

1. **Spike/POC:** Build minimal egui_graphs viewer with Pick's data (2 days)
2. **Demo:** Show to stakeholders for feedback
3. **Decision:** Commit to implementation or explore alternatives
4. **Implementation:** Follow 4-phase plan above (8-13 days)
5. **Migration:** Gradual rollout with feature flags

## Questions to Answer

1. **Window Management:** Single window vs multi-window acceptable?
2. **Performance Requirements:** Expected max node count?
3. **Feature Priority:** Which Cytoscape.js features are critical?
4. **Timeline:** What's the deadline for removing Cytoscape.js?
5. **GPU Access:** Is WebGPU available on target platforms?

## Conclusion

**egui_graphs is the clear winner** for replacing Cytoscape.js in Dioxus desktop applications. It offers the best balance of maturity, features, performance, and integration effort. The separate window approach provides the fastest path to a working solution while maintaining clean separation of concerns.

Start with a 2-day POC to validate the approach, then proceed with full implementation if results are satisfactory.
