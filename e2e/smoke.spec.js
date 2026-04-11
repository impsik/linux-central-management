import { test, expect } from '@playwright/test';

const USERNAME = process.env.PLAYWRIGHT_USERNAME || '';
const PASSWORD = process.env.PLAYWRIGHT_PASSWORD || '';

async function login(page) {
  await page.goto('/login');
  await expect(page.locator('#u')).toBeVisible();
  await expect(page.locator('#p')).toBeVisible();
  await page.locator('#u').fill(USERNAME);
  await page.locator('#p').fill(PASSWORD);
  await page.locator('#btn').click();
  await page.waitForURL((url) => !url.pathname.endsWith('/login'), { timeout: 15000 });
}

test('login page renders', async ({ page }) => {
  await page.goto('/login');
  await expect(page).toHaveTitle(/Login/i);
  await expect(page.locator('#u')).toBeVisible();
  await expect(page.locator('#p')).toBeVisible();
  await expect(page.locator('#btn')).toBeVisible();
});

test('authenticated boot-critical UI smoke', async ({ page }) => {
  test.skip(!USERNAME || !PASSWORD, 'Set PLAYWRIGHT_USERNAME and PLAYWRIGHT_PASSWORD to run authenticated smoke checks.');

  await login(page);

  await expect(page.locator('#settings-btn')).toBeVisible();
  await expect(page.locator('#nav-overview')).toBeVisible();
  await expect(page.locator('#nav-hosts')).toBeVisible();

  await page.locator('#settings-btn').click();
  await expect(page.locator('#settings-dropdown')).toBeVisible();
  await expect(page.locator('#admin-menu-item')).toBeVisible();

  await page.locator('#nav-hosts').click();
  await expect(page.locator('#hosts-table-tab')).toHaveClass(/active/);
  await expect(page.locator('#host-search')).toBeVisible();
  await expect(page.locator('#hosts-table-body')).toBeVisible();

  await page.locator('#nav-overview').click();
  await expect(page.locator('#server-info-tab')).toHaveClass(/active/);
  await expect(page.locator('#server-info-tab')).not.toContainText('Loading…', { timeout: 10000 });

  await page.locator('#settings-btn').click();
  await page.locator('#admin-menu-item').click();
  await expect(page.locator('#admin-tab')).toHaveClass(/active/);
  await expect(page.locator('#admin-users-table')).toBeVisible();
});
