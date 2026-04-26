# Feature Comparison: Cytoscape.js vs egui_graphs POC

## Visual Features

| Feature | Cytoscape.js | egui_graphs POC | Effort |
|---------|--------------|-----------------|--------|
| **Core Graph** |
| Node rendering | ✅ | ✅ | Done |
| Edge rendering | ✅ | ✅ | Done |
| Color-coded by type | ✅ | ✅ | Done |
| Interactive pan | ✅ | ✅ | Done |
| Interactive zoom (scroll) | ✅ | ✅ | Done |
| Interactive drag | ✅ | ✅ | Done |
| **Layout** |
| Force-directed | ❌ | ✅ | Done |
| Hierarchical (Dagre) | ✅ | ❌ | 1 day |
| Circular | ❌ | ❌ | 0.5 day |
| Grid | ❌ | ❌ | 0.5 day |
| Layout switcher UI | ❌ | ❌ | 0.5 day |
| **UI Controls** |
| Zoom in button | ✅ | ❌ | 2 hours |
| Zoom out button | ✅ | ❌ | 2 hours |
| Fit to screen button | ✅ | ❌ | 2 hours |
| Node count display | ✅ | ❌ | 1 hour |
| Edge count display | ✅ | ❌ | 1 hour |
| **Interaction** |
| Node selection (click) | ✅ | ✅ | Done |
| Node detail panel | ✅ | ✅ | Done |
| Node hover tooltip | ❌ | ❌ | 0.5 day |
| Double-click expand | ❌ | ❌ | 1 day |
| Right-click menu | ❌ | ❌ | 1 day |
| **Search & Filter** |
| Search by title | ❌ | ❌ | 1 day |
| Filter by node type | ✅ (broken) | ❌ | 1 day |
| Filter by confidence | ✅ (broken) | ❌ | 0.5 day |
| Filter by date | ✅ (broken) | ❌ | 0.5 day |
| **States** |
| Loading spinner | ✅ | ❌ | 2 hours |
| Error messages | ✅ | ❌ | 2 hours |
| Empty state | ❌ | ❌ | 1 hour |
| **Export** |
| Export to PNG | ❌ | ❌ | 0.5 day |
| Export to SVG | ❌ | ❌ | 1 day |
| Export to JSON | ❌ | ❌ | 2 hours |
| Copy to clipboard | ❌ | ❌ | 2 hours |
| **Performance** |
| 100 nodes @ 60 FPS | ✅ | ✅ | Done |
| 500 nodes @ 30 FPS | ? | ❌ | 1 day |
| 1000 nodes (LOD) | ? | ❌ | 1 day |
| **Integration** |
| Works in main app | ❌ BROKEN | ❌ | 2-3 days |
| Data from Dioxus | ✅ (broken) | ❌ | 2-3 days |
| Async loading | ✅ (broken) | ❌ | 1 day |

## Technical Architecture

| Aspect | Cytoscape.js | egui_graphs POC | Notes |
|--------|--------------|-----------------|-------|
| **Language** | JavaScript | Pure Rust | egui wins |
| **Bridge** | `document::eval` | None | egui wins |
| **Reliability** | ❌ Fails | ✅ Works | egui wins |
| **Deployment** | JS runtime | Single binary | egui wins |
| **Debugging** | Browser devtools | Rust debugger | egui wins |
| **Performance** | Good | Excellent | egui wins |
| **Library maturity** | Very mature | Stable | Cytoscape wins |
| **Community** | Large | Small | Cytoscape wins |

## Summary

### What We Gain by Switching
- ✅ Eliminates JavaScript bridge (root cause of blank page)
- ✅ Pure Rust = better performance + single binary
- ✅ Standard Rust debugging (no browser devtools needed)
- ✅ More reliable (no eval() failures)

### What We Need to Build
- 🔨 **Phase 1** (2-3 days): Basic integration with Dioxus
- 🔨 **Phase 2** (3-5 days): UI controls, layouts, filters, search
- 🔨 **Phase 3** (2-3 days): Performance, export, testing

### Effort Breakdown by Priority

**Must-Have (7 days)**:
- Integration with Dioxus: 2-3 days
- Zoom controls: 6 hours
- Loading/error states: 4 hours
- Graph stats: 2 hours
- Hierarchical layout: 1 day
- Filter support: 1 day

**Should-Have (3 days)**:
- Search: 1 day
- Export PNG: 0.5 day
- Node hover: 0.5 day
- Performance testing: 1 day

**Nice-to-Have (3 days)**:
- Multiple layouts: 1 day
- Advanced interactions: 2 days
- Keyboard shortcuts: Half day
- SVG export: 1 day

---

**Total Estimated Effort**: 8-13 days (depending on scope)

**Recommendation**: Start with Must-Have features, ship MVP, iterate on Should-Have and Nice-to-Have based on user feedback.
