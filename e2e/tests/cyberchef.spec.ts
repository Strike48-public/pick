import { test, expect, Page } from '@playwright/test';

/**
 * CyberChef Drag-and-Drop E2E Tests
 *
 * These tests verify the drag-and-drop functionality works correctly in the browser.
 * They complement the unit tests by testing actual DOM manipulation and mouse events.
 */

// Helper function to wait for navigation to CyberChef
async function navigateToCyberChef(page: Page) {
  // Click the CyberChef icon in sidebar (Bolt icon)
  await page.click('[aria-label*="CyberChef"], .sidebar button:has(svg)');
  await page.waitForSelector('.cyberchef-page', { timeout: 5000 });
}

// Helper function to get recipe chain items
async function getRecipeItems(page: Page): Promise<string[]> {
  const items = await page.$$eval('.recipe-chain-item .recipe-chain-name',
    (elements) => elements.map(el => el.textContent?.trim() || '')
  );
  return items;
}

// Helper function to drag an operation from the operations panel to the recipe
async function dragOperationToRecipe(page: Page, operationName: string) {
  // Find the operation in the operations list
  const operation = await page.locator(`.recipe-item:has-text("${operationName}")`).first();

  // Get recipe area bounds for drop target
  const recipeArea = await page.locator('.recipe-chain-area').first();
  const recipeBounds = await recipeArea.boundingBox();

  if (!recipeBounds) {
    throw new Error('Recipe area not found');
  }

  // Drag operation to center of recipe area
  await operation.dragTo(recipeArea, {
    targetPosition: {
      x: recipeBounds.width / 2,
      y: recipeBounds.height / 2
    }
  });

  // Wait for state update
  await page.waitForTimeout(100);
}

// Helper function to reorder items within recipe
async function reorderRecipeItem(page: Page, fromIndex: number, toIndex: number) {
  const items = await page.$$('.recipe-chain-item');

  if (fromIndex >= items.length || toIndex >= items.length) {
    throw new Error(`Invalid indices: from=${fromIndex}, to=${toIndex}, length=${items.length}`);
  }

  const sourceItem = items[fromIndex];
  const targetItem = items[toIndex];

  // Drag source item to target position
  await sourceItem.dragTo(targetItem, {
    targetPosition: { x: 10, y: 5 } // Top-left to insert before
  });

  // Wait for state update
  await page.waitForTimeout(100);
}

test.describe('CyberChef Drag and Drop', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await navigateToCyberChef(page);
  });

  test('should display CyberChef page with empty recipe', async ({ page }) => {
    await expect(page.locator('.cyberchef-page')).toBeVisible();
    await expect(page.locator('.recipe-chain-empty')).toBeVisible();
    await expect(page.locator('.recipe-chain-empty-icon')).toHaveText('⚡');
  });

  test('should show operations in categories', async ({ page }) => {
    await expect(page.locator('.recipe-category')).toHaveCount(7); // 7 categories
    await expect(page.locator('.recipe-item')).toHaveCount(20); // 20 operations
  });

  test('should add operation to recipe by clicking', async ({ page }) => {
    // Click an operation
    await page.click('.recipe-item:has-text("base64_decode")');

    // Verify it appears in recipe
    await expect(page.locator('.recipe-chain-item')).toHaveCount(1);
    const items = await getRecipeItems(page);
    expect(items).toEqual(['base64_decode']);
  });

  test('should add operation to recipe by dragging', async ({ page }) => {
    await dragOperationToRecipe(page, 'base64_decode');

    // Verify it appears in recipe
    await expect(page.locator('.recipe-chain-item')).toHaveCount(1);
    const items = await getRecipeItems(page);
    expect(items).toEqual(['base64_decode']);
  });

  test('should add multiple operations to recipe', async ({ page }) => {
    await dragOperationToRecipe(page, 'base64_decode');
    await dragOperationToRecipe(page, 'url_decode');
    await dragOperationToRecipe(page, 'hex_encode');

    const items = await getRecipeItems(page);
    expect(items).toEqual(['base64_decode', 'url_decode', 'hex_encode']);
  });

  test('should reorder operations within recipe', async ({ page }) => {
    // Add three operations
    await dragOperationToRecipe(page, 'base64_decode');
    await dragOperationToRecipe(page, 'url_decode');
    await dragOperationToRecipe(page, 'hex_encode');

    // Reorder: move last item (hex_encode) to first position
    await reorderRecipeItem(page, 2, 0);

    const items = await getRecipeItems(page);
    expect(items).toEqual(['hex_encode', 'base64_decode', 'url_decode']);
  });

  test('should show insert indicator when dragging over recipe items', async ({ page }) => {
    // Add two operations
    await dragOperationToRecipe(page, 'base64_decode');
    await dragOperationToRecipe(page, 'url_decode');

    // Start dragging the first item
    const firstItem = await page.locator('.recipe-chain-item').first();
    await firstItem.hover();
    await page.mouse.down();

    // Move over the second item
    const secondItem = await page.locator('.recipe-chain-item').nth(1);
    await secondItem.hover();

    // Verify insert indicator appears
    await expect(page.locator('.recipe-insert-indicator')).toBeVisible();

    // Release mouse
    await page.mouse.up();
  });

  test('should toggle operation enabled/disabled', async ({ page }) => {
    await dragOperationToRecipe(page, 'base64_decode');

    const toggleButton = page.locator('.recipe-chain-toggle').first();

    // Initially enabled (checkmark)
    await expect(toggleButton).toHaveClass(/enabled/);
    await expect(toggleButton).toHaveText('✓');

    // Click to disable
    await toggleButton.click();
    await expect(toggleButton).toHaveClass(/disabled/);
    await expect(toggleButton).toHaveText('−');

    // Click to re-enable
    await toggleButton.click();
    await expect(toggleButton).toHaveClass(/enabled/);
    await expect(toggleButton).toHaveText('✓');
  });

  test('should remove operation with × button', async ({ page }) => {
    await dragOperationToRecipe(page, 'base64_decode');
    await dragOperationToRecipe(page, 'url_decode');

    // Click remove button on first item
    await page.click('.recipe-chain-item:first-child .recipe-chain-remove');

    // Verify only one item remains
    await expect(page.locator('.recipe-chain-item')).toHaveCount(1);
    const items = await getRecipeItems(page);
    expect(items).toEqual(['url_decode']);
  });

  test('should clear entire recipe', async ({ page }) => {
    await dragOperationToRecipe(page, 'base64_decode');
    await dragOperationToRecipe(page, 'url_decode');
    await dragOperationToRecipe(page, 'hex_encode');

    // Click clear button
    await page.click('.clear-recipe-btn');

    // Verify recipe is empty
    await expect(page.locator('.recipe-chain-empty')).toBeVisible();
    await expect(page.locator('.recipe-chain-item')).toHaveCount(0);
  });

  test('should execute recipe and show output', async ({ page }) => {
    // Add base64_decode operation
    await dragOperationToRecipe(page, 'base64_decode');

    // Enter base64-encoded input
    await page.fill('.input-panel textarea', 'SGVsbG8gV29ybGQ=');

    // Wait for auto-bake
    await page.waitForTimeout(500);

    // Verify output
    const output = await page.locator('.output-panel textarea').inputValue();
    expect(output).toBe('Hello World');
  });

  test('should chain multiple operations', async ({ page }) => {
    // Add operations: base64_decode → url_decode
    await dragOperationToRecipe(page, 'base64_decode');
    await dragOperationToRecipe(page, 'url_decode');

    // Enter double-encoded input
    await page.fill('.input-panel textarea', 'SGVsbG8lMjBXb3JsZA==');

    // Wait for auto-bake
    await page.waitForTimeout(500);

    // Verify chained output
    const output = await page.locator('.output-panel textarea').inputValue();
    expect(output).toBe('Hello World');
  });

  test('should skip disabled operations in chain', async ({ page }) => {
    // Add three operations
    await dragOperationToRecipe(page, 'base64_decode');
    await dragOperationToRecipe(page, 'url_decode');
    await dragOperationToRecipe(page, 'hex_encode');

    // Disable middle operation (url_decode)
    await page.locator('.recipe-chain-toggle').nth(1).click();

    // Enter input
    await page.fill('.input-panel textarea', 'SGVsbG8=');

    // Wait for auto-bake
    await page.waitForTimeout(500);

    // Verify only base64_decode and hex_encode ran (url_decode skipped)
    const output = await page.locator('.output-panel textarea').inputValue();
    // "Hello" → hex_encode → "48656c6c6f"
    expect(output).toBe('48656c6c6f');
  });

  test('should search and filter operations', async ({ page }) => {
    // Type in search box
    await page.fill('#search', 'decode');

    // Verify filtered results
    const visibleOperations = await page.$$eval('.recipe-item:visible',
      elements => elements.length
    );
    expect(visibleOperations).toBeGreaterThan(0);
    expect(visibleOperations).toBeLessThan(20); // Less than total
  });

  test('should resize input/output panels', async ({ page }) => {
    // Get initial heights
    const inputPanel = page.locator('.input-panel');
    const initialHeight = await inputPanel.evaluate(el => el.getBoundingClientRect().height);

    // Drag resize handle
    const resizeHandle = page.locator('.io-resize-handle');
    const handleBounds = await resizeHandle.boundingBox();

    if (!handleBounds) {
      throw new Error('Resize handle not found');
    }

    // Drag down 100px
    await page.mouse.move(handleBounds.x + handleBounds.width / 2, handleBounds.y);
    await page.mouse.down();
    await page.mouse.move(handleBounds.x, handleBounds.y + 100);
    await page.mouse.up();

    // Verify height changed
    const newHeight = await inputPanel.evaluate(el => el.getBoundingClientRect().height);
    expect(Math.abs(newHeight - initialHeight)).toBeGreaterThan(50);
  });

  test('should persist enabled/disabled state during reorder', async ({ page }) => {
    // Add three operations
    await dragOperationToRecipe(page, 'base64_decode');
    await dragOperationToRecipe(page, 'url_decode');
    await dragOperationToRecipe(page, 'hex_encode');

    // Disable middle operation
    await page.locator('.recipe-chain-toggle').nth(1).click();

    // Reorder: move last to first
    await reorderRecipeItem(page, 2, 0);

    // Verify url_decode is still disabled (now at index 2)
    const toggleButton = page.locator('.recipe-chain-toggle').nth(2);
    await expect(toggleButton).toHaveClass(/disabled/);
  });
});

test.describe('CyberChef Edge Cases', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await navigateToCyberChef(page);
  });

  test('should handle rapid drag operations', async ({ page }) => {
    // Rapidly add multiple operations
    for (let i = 0; i < 5; i++) {
      await dragOperationToRecipe(page, 'base64_decode');
    }

    // Verify all added
    await expect(page.locator('.recipe-chain-item')).toHaveCount(5);
  });

  test('should handle empty input gracefully', async ({ page }) => {
    await dragOperationToRecipe(page, 'base64_decode');

    // Leave input empty
    await page.fill('.input-panel textarea', '');

    // Output should also be empty
    const output = await page.locator('.output-panel textarea').inputValue();
    expect(output).toBe('');
  });

  test('should show error for invalid input', async ({ page }) => {
    await dragOperationToRecipe(page, 'base64_decode');

    // Enter invalid base64
    await page.fill('.input-panel textarea', 'not valid base64!!!');

    // Wait for error
    await page.waitForTimeout(500);

    // Check for error banner
    await expect(page.locator('.error-banner')).toBeVisible();
  });
});
