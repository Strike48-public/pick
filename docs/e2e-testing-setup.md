# E2E Testing Setup with Playwright

## Overview

Playwright end-to-end tests verify the CyberChef drag-and-drop functionality works correctly in real browsers.

## Quick Start

```bash
cd e2e
./run-tests.sh
```

## Test Modes

### Headless (CI/CD)
```bash
./run-tests.sh headless
```
Runs tests without visible browser. Fast, suitable for CI.

### Headed (Debugging)
```bash
./run-tests.sh headed
```
Opens browser window so you can see what's happening.

### Interactive UI
```bash
./run-tests.sh ui
```
Opens Playwright UI for interactive test development.

### Debug Mode
```bash
./run-tests.sh debug
```
Step through tests one action at a time.

### CyberChef Only
```bash
./run-tests.sh cyberchef
```
Run only CyberChef-specific tests.

## What Gets Tested

### ✅ 21 Test Cases Covering:

**Basic Operations:**
1. Display CyberChef page
2. Show operations in categories
3. Add operation by clicking
4. Add operation by dragging

**Drag-and-Drop Core:**
5. Add multiple operations
6. Reorder operations
7. Show insert indicator
8. Persist state during reorder

**Recipe Management:**
9. Toggle enabled/disabled
10. Remove with × button
11. Clear entire recipe

**Execution:**
12. Execute single operation
13. Chain multiple operations
14. Skip disabled operations

**UI Features:**
15. Search/filter operations
16. Resize panels

**Edge Cases:**
17. Rapid drag operations
18. Empty input handling
19. Invalid input errors

## Test Architecture

```
e2e/
├── tests/
│   └── cyberchef.spec.ts    # CyberChef tests
├── playwright.config.ts      # Playwright configuration
├── package.json              # Dependencies
├── run-tests.sh              # Test runner script
└── README.md                 # Documentation
```

## Integration with CI

Tests run automatically on:
- Pull requests
- Pushes to main

GitHub Actions workflow:
```yaml
- name: Run E2E Tests
  run: |
    cd e2e
    npm install
    npx playwright install chromium
    npm test
```

## Debugging Failed Tests

### View test artifacts
```bash
ls test-results/
```

Contains:
- Screenshots (on failure)
- Videos (on failure)
- Traces (on retry)

### View trace
```bash
npx playwright show-trace test-results/<test-name>/trace.zip
```

### Run specific test
```bash
npx playwright test --grep "should reorder operations"
```

## Writing New Tests

1. Create test file: `tests/my-feature.spec.ts`
2. Use test helpers from `cyberchef.spec.ts`
3. Run locally: `./run-tests.sh headed`
4. Commit when passing

## Best Practices

1. **Use data-testid** for stable selectors
2. **Wait for state changes** after drag operations
3. **Test real user flows** not implementation details
4. **Keep tests independent** - each test should work in isolation
5. **Use page object pattern** for complex interactions

## Performance

- **Unit tests**: < 1 second (18 tests)
- **E2E tests**: ~30-60 seconds (21 tests)
- **Total coverage**: 39 automated tests

Run unit tests frequently, E2E tests before commits.

---

## Capturing UI Media for PRs

The connector UI is a Dioxus liveview app served by `pentest-web` on
`http://localhost:3000/app`, and it boots to a "Connect to Strike48" gate: the
sidebar, Settings, and Tools panel only render after connecting. The e2e suite
above targets a different surface, so a dedicated helper drives the connector UI
and produces screenshots + a GIF for pull-request documentation.

`scripts/capture-ui.sh` (a thin wrapper over `scripts/capture_ui.py`) launches
the web app, connects to a local Strike48 studio, navigates to a view, runs an
optional interaction, and writes media to `docs/assets/<feature>/`.

### Requirements

Same Playwright + Chromium used elsewhere, plus `ffmpeg` for GIF conversion:

```bash
pip install playwright && playwright install chromium   # in the mise python env
```

Connection settings come from `--host` / `--tenant`, else `STRIKE48_HOST` /
`STRIKE48_TENANT`, else the repo `.env` (gitignored). Point it at a **local**
studio (e.g. `wss://studio.strike48.test`), not a production tenant.

### Usage

```bash
# Screenshots + GIF of an install with the elapsed/estimate progress bar
scripts/capture-ui.sh --feature install-progress \
    --view Settings --interaction install-first-tool

# A static view, screenshots only (no GIF)
scripts/capture-ui.sh --feature dashboard --view Dashboard --no-video
```

Artifacts land in `docs/assets/<feature>/` (`NN-*.png` frames plus
`<feature>.gif`). The intermediate WebM/palette scratch files are removed.

### Committing and referencing media

Per project convention, commit the intended PNG/GIF into the PR diff and
reference them with a repo-relative path in the PR body:

```markdown
![install progress](docs/assets/install-progress/02-installing.png)
```

Commit only the frames you actually reference; delete the rest so the diff and
repo history stay lean. Do not commit `.webm` scratch files.

### Adding a new interaction

Interactions live in `scripts/capture_ui.py` under the `INTERACTIONS` map. Add a
`interaction_<name>(page, out_dir)` function that drives the feature and drops
screenshots, then register it in the map; it becomes selectable via
`--interaction <name>`.
