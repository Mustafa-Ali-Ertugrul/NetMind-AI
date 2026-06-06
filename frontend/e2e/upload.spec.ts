import { test, expect } from '@playwright/test';

test.describe('upload page', () => {
  test('renders upload form', async ({ page }) => {
    await page.goto('/upload');
    await expect(page.getByRole('heading', { name: 'Upload PCAP' })).toBeVisible();
    // Dropzone should be visible (it contains "Drag & drop" text or an input)
    await expect(page.locator('input[type="file"]')).toBeVisible();
  });
});
