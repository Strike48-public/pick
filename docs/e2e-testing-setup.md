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
