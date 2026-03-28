# CyberChef Drag-and-Drop Testing Guide

## Automated Tests

Run the test suite to verify the drag-and-drop logic:

```bash
cargo test --package pentest-ui cyberchef_sortable_tests
```

**All 18 tests must pass** before merging any changes to the sortable logic.

## Test Coverage

The automated tests cover:

### Basic Operations (3 items: A, B, C)
- ✅ Drag first to second (before/after)
- ✅ Drag first to third (before/after)
- ✅ Drag second to first (before/after)
- ✅ Drag second to third (before/after)
- ✅ Drag third to first (before/after)
- ✅ Drag third to second (before/after)
- ✅ Drag onto self (no-op cases)

### Edge Cases
- ✅ Single item list
- ✅ Two item swap
- ✅ Longer lists (5+ items)
- ✅ Moving forward multiple positions
- ✅ Moving backward multiple positions

## Manual Testing Checklist

### Scenario 1: Adding Operations from Panel
1. Start with empty recipe
2. Drag "Base64 Decode" from Operations → Drop in recipe area
   - **Expected:** Operation appears in recipe
3. Drag "URL Decode" from Operations → Drop in recipe area
   - **Expected:** Second operation appears below first
4. Drag "Hex Encode" from Operations → Drop in recipe area
   - **Expected:** Third operation appears at bottom

**Verify:** Recipe shows [Base64 Decode, URL Decode, Hex Encode]

### Scenario 2: Reordering Within Recipe
1. Start with recipe: [Base64 Decode, URL Decode, Hex Encode]
2. Drag "Hex Encode" (3rd) → Drop above "Base64 Decode" (1st)
   - **Expected:** [Hex Encode, Base64 Decode, URL Decode]
3. Drag "URL Decode" (3rd) → Drop above "Hex Encode" (1st)
   - **Expected:** [URL Decode, Hex Encode, Base64 Decode]

**Verify:** Operations reorder without duplication or deletion

### Scenario 3: Insert Between Operations
1. Start with recipe: [A, B, C]
2. Drag "D" from Operations → Hover between A and B until blue line appears
   - **Expected:** Blue line shows between A and B
3. Drop
   - **Expected:** Recipe becomes [A, D, B, C]
4. Drag "E" from Operations → Hover between C and end until blue line appears
   - **Expected:** Blue line shows after C
5. Drop
   - **Expected:** Recipe becomes [A, D, B, C, E]

**Verify:** New operations insert at correct positions

### Scenario 4: Removing Operations by Drag-Out
1. Start with recipe: [A, B, C, D]
2. Drag "B" outside the recipe panel (into Operations or empty space)
3. Release mouse
   - **Expected:** Recipe becomes [A, C, D]
4. Drag "D" outside the recipe panel
5. Release mouse
   - **Expected:** Recipe becomes [A, C]

**Verify:** Operations removed when dragged outside

### Scenario 5: No-Op Cases (Shouldn't Change)
1. Start with recipe: [A, B, C]
2. Drag "B" and drop it on itself
   - **Expected:** No change, still [A, B, C]
3. Drag "A" and drop right after "A" (between A and B)
   - **Expected:** No change, still [A, B, C]
4. Drag "C" and drop right before "C" (between B and C)
   - **Expected:** No change, still [A, B, C]

**Verify:** No unnecessary reordering when dropping adjacent to origin

### Scenario 6: Complex Reordering
1. Start with recipe: [Hash MD5, Base64 Encode, URL Encode, ROT13, Hex Decode]
2. Drag "ROT13" (4th) → Drop before "Base64 Encode" (2nd)
   - **Expected:** [Hash MD5, ROT13, Base64 Encode, URL Encode, Hex Decode]
3. Drag "Hex Decode" (5th) → Drop before "Hash MD5" (1st)
   - **Expected:** [Hex Decode, Hash MD5, ROT13, Base64 Encode, URL Encode]
4. Drag "Base64 Encode" (4th) → Drop after "Hex Decode" (1st)
   - **Expected:** [Hex Decode, Base64 Encode, Hash MD5, ROT13, URL Encode]

**Verify:** Multiple reorders work correctly in sequence

### Scenario 7: Enable/Disable During Drag
1. Start with recipe: [A, B, C]
2. Disable "B" (click checkmark → becomes dash)
3. Drag "C" → Drop before "A"
   - **Expected:** [C, A, B] with B still disabled
4. Enable "B" again
   - **Expected:** All operations enabled

**Verify:** Enable/disable state persists during reordering

## Bug That Was Fixed

**Issue:** Dragging an operation to a drop zone would sometimes delete the operation at that position.

**Root Cause:** Index calculation after `remove()` was incorrect when `insert_before` was always true.

**Fix:** Improved logic to properly adjust target index based on:
- Whether inserting before or after
- Whether moving forward or backward
- Accounting for the index shift after removal

**Test:** Run `cargo test cyberchef_sortable_tests` - all 18 tests verify correct behavior.

## Debugging Tips

If drag-and-drop behaves unexpectedly:

1. **Check console logs** - Errors will appear in browser console
2. **Verify state** - Add temporary logging to `handle_drag_end()`
3. **Run unit tests** - Ensure all 18 tests pass
4. **Test edge cases** - Single item, two items, empty recipe
5. **Check for race conditions** - Rapid dragging might cause issues

## Performance Notes

- Drag operations are handled synchronously
- Auto-bake triggers on every reorder if enabled
- For large recipes (50+ ops), consider disabling auto-bake during editing
