# egui_graphs Integration Roadmap - Feature Parity with Cytoscape.js

## Current State

### What Cytoscape.js Has (Broken)
1. ✅ Node rendering with colors by type
2. ✅ Edge rendering with relationship types
3. ✅ Interactive pan/zoom/drag
4. ✅ Node selection with detail panel
5. ✅ Dagre hierarchical layout
6. ✅ Graph stats display (node/edge counts)
7. ✅ Zoom controls (+/-/fit buttons)
8. ✅ Loading states
9. ✅ Error states
10. ✅ Async data loading from MockEvidenceClient
11. ✅ Filter support (via EvidenceFilters)
12. ❌ **BROKEN**: JavaScript bridge via `document::eval` fails

### What egui_graphs POC Has (Working)
1. ✅ Node rendering with colors by type
2. ✅ Edge rendering
3. ✅ Interactive pan/zoom/drag
4. ✅ Node selection with detail panel
5. ✅ Force-directed layout (automatic)
6. ✅ Pure Rust - no JavaScript bridge
7. ❌ Missing: Zoom controls UI
8. ❌ Missing: Graph stats display
9. ❌ Missing: Loading states
10. ❌ Missing: Error states
11. ❌ Missing: Async data loading
12. ❌ Missing: Filter support
13. ❌ Missing: Integration with Dioxus app

---

## Path to Parity - 3 Phase Approach

### Phase 1: Basic Integration (2-3 days)
**Goal**: Get egui_graphs working alongside the Dioxus desktop app

#### 1.1 Dual-Window Architecture
- Create separate egui window that runs alongside Dioxus
- Use channels for communication between Dioxus and egui
- Data flow: Dioxus → Channel → egui window

```rust
// In main.rs
let (tx, rx) = mpsc::channel();
thread::spawn(move || run_egui_window(rx));
// Dioxus sends graph updates via tx
```

#### 1.2 Basic Data Bridge
- Add channel sender to Dioxus app state
- Send KnowledgeGraph updates from Dioxus to egui
- egui window redraws when it receives updates

**Deliverable**: Standalone egui window showing graph, updates when Dioxus sends data

---

### Phase 2: Feature Parity (3-5 days)
**Goal**: Match all Cytoscape.js features

#### 2.1 UI Components (1 day)
- [ ] Add zoom control buttons (+/-/fit)
- [ ] Add graph stats panel (node/edge counts)
- [ ] Add loading spinner overlay
- [ ] Add error message display
- [ ] Style to match Pick's theme

#### 2.2 Layout Options (1 day)
- [ ] Implement hierarchical layout (like Dagre)
- [ ] Add layout switcher UI (hierarchical/force-directed/circular/grid)
- [ ] Persist layout preference

```rust
enum LayoutType {
    ForceDirected,
    Hierarchical,
    Circular,
    Grid,
}
```

#### 2.3 Filtering System (1 day)
- [ ] Port `EvidenceFilters` support from Cytoscape impl
- [ ] Add filter UI panel (checkboxes for node types)
- [ ] Real-time graph filtering without reload

```rust
struct GraphFilters {
    node_types: HashSet<NodeType>,
    min_confidence: f32,
    date_range: Option<(DateTime, DateTime)>,
}
```

#### 2.4 Node Interaction (1 day)
- [ ] Enhanced node detail panel (match Cytoscape styling)
- [ ] Node hover tooltips
- [ ] Double-click to expand/collapse related nodes
- [ ] Right-click context menu

#### 2.5 Search & Navigation (1 day)
- [ ] Search bar to find nodes by title/description
- [ ] Highlight search results
- [ ] Center on selected node
- [ ] Breadcrumb navigation for node relationships

**Deliverable**: Feature-complete graph visualization matching Cytoscape.js capabilities

---

### Phase 3: Polish & Performance (2-3 days)
**Goal**: Production-ready integration

#### 3.1 Performance Optimization (1 day)
- [ ] Test with large graphs (100+ nodes)
- [ ] Optimize layout algorithm for performance
- [ ] Implement level-of-detail rendering (hide labels when zoomed out)
- [ ] Add progressive loading for huge graphs

**Target Performance**:
- 100 nodes: 60 FPS
- 500 nodes: 30+ FPS
- 1000 nodes: render with LOD optimizations

#### 3.2 Export & Share (1 day)
- [ ] Export graph to PNG (screenshot)
- [ ] Export graph to SVG (vector)
- [ ] Export graph data to JSON
- [ ] Copy graph to clipboard

#### 3.3 Keyboard Shortcuts (half day)
```
Space: Fit to screen
+/-: Zoom in/out
Arrows: Pan
Esc: Deselect node
F: Focus on selected node
/: Open search
```

#### 3.4 Testing & Documentation (1 day)
- [ ] Integration tests for data bridge
- [ ] Unit tests for layout algorithms
- [ ] User documentation
- [ ] Developer documentation (how to extend)

**Deliverable**: Production-ready, tested, documented graph visualization

---

## Alternative Approach: Replace Dioxus Component

Instead of dual-window, embed egui directly into Dioxus using `egui-winit`:

**Pros:**
- Single window experience
- Cleaner architecture
- Easier state management

**Cons:**
- More complex integration
- May require Dioxus plugin development
- Longer timeline (+2-3 days)

**Recommendation**: Start with dual-window (simpler), migrate to embedded later if needed.

---

## Implementation Priority

### Must-Have (Blocking Launch)
1. Basic integration (Phase 1)
2. Loading/error states (Phase 2.1)
3. Node selection & details (Phase 2.4)
4. Zoom controls (Phase 2.1)

### Should-Have (For MVP)
5. Hierarchical layout (Phase 2.2)
6. Filtering (Phase 2.3)
7. Search (Phase 2.5)
8. Export PNG (Phase 3.2)

### Nice-to-Have (Post-MVP)
9. Multiple layouts (Phase 2.2)
10. Advanced interactions (Phase 2.4)
11. Keyboard shortcuts (Phase 3.3)
12. SVG export (Phase 3.2)

---

## Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| Performance with large graphs | High | Implement LOD, progressive loading |
| egui-Dioxus integration complexity | Medium | Start with separate window, iterate |
| Layout algorithm quality | Medium | Use proven algorithms from petgraph |
| User learning curve (new UI) | Low | Match Cytoscape UX patterns |

---

## Timeline Summary

| Phase | Duration | Deliverable |
|-------|----------|-------------|
| Phase 1 | 2-3 days | Basic integration, dual-window |
| Phase 2 | 3-5 days | Feature parity with Cytoscape.js |
| Phase 3 | 2-3 days | Polish, performance, testing |
| **Total** | **8-13 days** | Production-ready replacement |

---

## Next Immediate Steps

1. **Today**: Review this roadmap, decide on approach
2. **Tomorrow**: Start Phase 1.1 (dual-window architecture)
3. **Day 3**: Complete Phase 1.2 (data bridge)
4. **Day 4-6**: Phase 2 feature implementation
5. **Day 7-9**: Phase 3 polish & testing

---

## Decision Points

### Day 1 Decision
- [ ] Approve dual-window approach vs embedded approach
- [ ] Prioritize feature list (must/should/nice-to-have)

### Day 3 Decision (After Phase 1)
- [ ] Validate data bridge works correctly
- [ ] Decide if we continue or pivot to embedded approach

### Day 6 Decision (After Phase 2)
- [ ] User acceptance testing
- [ ] Identify any missing critical features

---

## Success Criteria

- [ ] No blank Evidence page (root issue resolved)
- [ ] All Cytoscape.js features working
- [ ] Performance: 60 FPS with 100 nodes
- [ ] No JavaScript bridge dependency
- [ ] User can navigate and interact with graph naturally
- [ ] Filters work correctly
- [ ] Export functionality works
- [ ] Tests pass with 80%+ coverage

---

**Date**: 2026-04-14  
**Author**: Claude Sonnet 4.5  
**Status**: READY FOR REVIEW
