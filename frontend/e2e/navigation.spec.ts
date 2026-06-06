import { test, expect } from '@playwright/test';

test.describe('SPA navigation', () => {
  test('dashboard renders', async ({ page }) => {
    await page.goto('/');
    // Sidebar layout is always rendered regardless of API state
    await expect(page.getByText('NetMind AI')).toBeVisible();
    await expect(page.getByRole('link', { name: 'Dashboard' })).toBeVisible();
  });

  test('sidebar navigates to upload', async ({ page }) => {
    await page.goto('/');
    await page.getByRole('link', { name: 'Upload PCAP' }).click();
    await expect(page.getByRole('heading', { name: 'Upload PCAP' })).toBeVisible();
  });

  test('sidebar navigates to storage', async ({ page }) => {
    await page.goto('/');
    await page.getByRole('link', { name: 'Storage' }).click();
    await expect(page).toHaveURL(/\/storage$/);
    // Without backend the page shows an error — assert fallback text so the route is reached
    await expect(page.getByText(/Failed to load storage status|Loading storage status/i)).toBeVisible();
  });

  test('unknown route shows not found', async ({ page }) => {
    await page.goto('/this-does-not-exist');
    await expect(page.getByText(/404|not found/i)).toBeVisible();
  });
});
