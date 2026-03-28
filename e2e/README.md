# Pick E2E Tests

End-to-end tests for Pick using Playwright.

## Setup

Install dependencies:

```bash
cd e2e
npm install
npx playwright install chromium
```

## Running Tests

### Run all tests (headless)
```bash
npm test
```

### Run with browser visible
```bash
npm run test:headed
```

### Run with Playwright UI (interactive)
```bash
npm run test:ui
```

### Run only CyberChef tests
```bash
npm run test:cyberchef
```

### Debug mode (step through tests)
```bash
npm run test:debug
```

## Test Coverage

### CyberChef Drag-and-Drop Tests (`tests/cyberchef.spec.ts`)

**Basic Functionality:**
- ✅ Display CyberChef page with empty recipe
- ✅ Show operations in categories (7 categories, 20 operations)
- ✅ Add operation by clicking
- ✅ Add operation by dragging

**Drag-and-Drop:**
- ✅ Add multiple operations to recipe
- ✅ Reorder operations within recipe
- ✅ Show insert indicator when dragging
- ✅ Persist enabled/disabled state during reorder

**Recipe Management:**
- ✅ Toggle operation enabled/disabled
- ✅ Remove operation with × button
- ✅ Clear entire recipe

**Execution:**
- ✅ Execute single operation
- ✅ Chain multiple operations
- ✅ Skip disabled operations in chain

**UI Features:**
- ✅ Search and filter operations
- ✅ Resize input/output panels

**Edge Cases:**
- ✅ Handle rapid drag operations
- ✅ Handle empty input gracefully
- ✅ Show error for invalid input

## CI Integration

Tests run automatically on:
- Pull requests
- Pushes to main branch

Test results are available in the GitHub Actions workflow.

## Troubleshooting

### Tests timeout
- Increase timeout in `playwright.config.ts` (`timeout` option)
- Check that Pick starts successfully (`webServer.command`)

### WebServer won't start
- Ensure `.env` file is configured correctly
- Check that port 8080 is available
- Run `./run-pentest.sh headless dev` manually to verify

### Drag-and-drop tests fail
- Check browser console for JavaScript errors
- Verify DOM selectors in test match actual HTML structure
- Run tests in headed mode to see what's happening: `npm run test:headed`

### Screenshots/videos
Failed tests automatically save:
- Screenshots in `test-results/`
- Videos in `test-results/`
- Traces in `test-results/` (view with `npx playwright show-trace <file>`)

## Writing New Tests

1. Create new `.spec.ts` file in `tests/`
2. Import test helpers: `import { test, expect } from '@playwright/test';`
3. Write test cases following Playwright patterns
4. Run locally before committing: `npm test`

### Example Test Structure

```typescript
import { test, expect } from '@playwright/test';

test.describe('Feature Name', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    // Setup code
  });

  test('should do something', async ({ page }) => {
    // Test code
    await expect(page.locator('.selector')).toBeVisible();
  });
});
```

## Resources

- [Playwright Documentation](https://playwright.dev)
- [Playwright Test API](https://playwright.dev/docs/api/class-test)
- [Debugging Tests](https://playwright.dev/docs/debug)
