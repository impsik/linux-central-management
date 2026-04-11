import { test, expect } from '@playwright/test';

const ADMIN_USERNAME = process.env.PLAYWRIGHT_USERNAME || '';
const ADMIN_PASSWORD = process.env.PLAYWRIGHT_PASSWORD || '';
const OWNER_VIEWER_USERNAME = process.env.PLAYWRIGHT_OWNER_USERNAME || '';
const OWNER_VIEWER_PASSWORD = process.env.PLAYWRIGHT_OWNER_PASSWORD || '';

async function loginAs(page, username, password) {
  await page.goto('/login');
  await expect(page.locator('#u')).toBeVisible();
  await expect(page.locator('#p')).toBeVisible();
  await page.locator('#u').fill(username);
  await page.locator('#p').fill(password);
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
  test.skip(!ADMIN_USERNAME || !ADMIN_PASSWORD, 'Set PLAYWRIGHT_USERNAME and PLAYWRIGHT_PASSWORD to run authenticated smoke checks.');

  await loginAs(page, ADMIN_USERNAME, ADMIN_PASSWORD);

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

test('admin can save host metadata on seeded host', async ({ page }) => {
  test.skip(!ADMIN_USERNAME || !ADMIN_PASSWORD, 'Set PLAYWRIGHT_USERNAME and PLAYWRIGHT_PASSWORD to run authenticated smoke checks.');

  await loginAs(page, ADMIN_USERNAME, ADMIN_PASSWORD);
  await expect(page.locator('#hosts .host-item')).toContainText('ci-alice-host', { timeout: 15000 });
  await page.locator('#hosts .host-item', { hasText: 'ci-alice-host' }).click();

  await expect(page.locator('#host-meta-role')).toBeVisible();
  await expect(page.locator('#host-meta-owner')).toBeVisible();

  await page.locator('#host-meta-role').fill('web-smoke');
  await page.locator('#host-meta-save').click();

  await expect(page.locator('#host-meta-status')).toContainText('Saved.', { timeout: 10000 });
  await expect(page.locator('#server-info-labels')).toContainText('role:');
  await expect(page.locator('#server-info-labels')).toContainText('web-smoke');
});

test('owner-scoped readonly user only sees owned seeded host', async ({ page }) => {
  test.skip(!OWNER_VIEWER_USERNAME || !OWNER_VIEWER_PASSWORD, 'Set PLAYWRIGHT_OWNER_USERNAME and PLAYWRIGHT_OWNER_PASSWORD to run owner-scope smoke checks.');

  await loginAs(page, OWNER_VIEWER_USERNAME, OWNER_VIEWER_PASSWORD);
  await expect(page.locator('#hosts .host-item')).toContainText('ci-alice-host', { timeout: 15000 });
  await expect(page.locator('#hosts .host-item')).not.toContainText('ci-bob-host');

  await page.locator('#nav-hosts').click();
  await expect(page.locator('#hosts-table-tab')).toHaveClass(/active/);
  await expect(page.locator('#hosts-visible-counter')).toContainText('1 / 1', { timeout: 10000 });
});

test('admin can create and remove a user from admin panel', async ({ page }) => {
  test.skip(!ADMIN_USERNAME || !ADMIN_PASSWORD, 'Set PLAYWRIGHT_USERNAME and PLAYWRIGHT_PASSWORD to run authenticated smoke checks.');

  const username = `pw-smoke-${Date.now()}`;
  const password = 'pw-smoke-pass-123';

  await loginAs(page, ADMIN_USERNAME, ADMIN_PASSWORD);
  await page.locator('#settings-btn').click();
  await page.locator('#admin-menu-item').click();
  await expect(page.locator('#admin-tab')).toHaveClass(/active/);

  await page.locator('#register-username').fill(username);
  await page.locator('#register-password').fill(password);
  await page.locator('#register-role').selectOption('readonly');
  await page.locator('#register-user-btn').click();

  await expect(page.locator('#register-status')).toContainText(`User ${username} created as readonly.`, { timeout: 10000 });
  await expect(page.locator('#admin-users-table')).toContainText(username, { timeout: 10000 });

  page.once('dialog', (dialog) => dialog.accept());
  await page.locator(`[data-user-remove-enhanced="${username}"]`).click();
  await expect(page.locator('#admin-users-table')).not.toContainText(username, { timeout: 10000 });
});
