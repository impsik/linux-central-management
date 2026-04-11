import { test, expect } from '@playwright/test';

const ADMIN_USERNAME = process.env.PLAYWRIGHT_USERNAME || '';
const ADMIN_PASSWORD = process.env.PLAYWRIGHT_PASSWORD || '';
const OWNER_VIEWER_USERNAME = process.env.PLAYWRIGHT_OWNER_USERNAME || '';
const OWNER_VIEWER_PASSWORD = process.env.PLAYWRIGHT_OWNER_PASSWORD || '';
const SAMPLE_SSH_PUBKEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB8x7SxgY8m0Q4X8pM0lJx2Y4vWw2vQ2mYwK9f1Wm0a1 playwright-smoke@example';

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

test('ssh key deploy request can be reviewed and rejected by admin', async ({ browser }) => {
  test.skip(
    !ADMIN_USERNAME || !ADMIN_PASSWORD || !OWNER_VIEWER_USERNAME || !OWNER_VIEWER_PASSWORD,
    'Set admin and owner-viewer Playwright credentials to run SSH request smoke checks.'
  );

  const keyName = `pw-ssh-${Date.now()}`;
  const ownerPage = await browser.newPage();
  const adminPage = await browser.newPage();

  try {
    await loginAs(ownerPage, OWNER_VIEWER_USERNAME, OWNER_VIEWER_PASSWORD);
    await ownerPage.locator('#nav-sshkeys').click();
    await expect(ownerPage.locator('#sshkeys-tab')).toHaveClass(/active/);

    await ownerPage.locator('#sshkey-name').fill(keyName);
    await ownerPage.locator('#sshkey-pub').fill(SAMPLE_SSH_PUBKEY);
    await ownerPage.locator('#sshkey-add').click();
    await expect(ownerPage.locator('#sshkeys-table')).toContainText(keyName, { timeout: 10000 });

    await ownerPage.locator('#sshkeys-table tr', { hasText: keyName }).click();
    await ownerPage.locator('#sshkey-hosts-open').click();
    await expect(ownerPage.locator('#sshkey-hosts-panel')).toBeVisible();
    await ownerPage.locator('#sshkey-hosts-list label', { hasText: 'ci-alice-host' }).locator('input[type="checkbox"]').check();
    await ownerPage.locator('#sshkey-request-deploy').click();

    await expect(ownerPage.locator('#sshkey-requests-table')).toContainText('pending', { timeout: 10000 });
    await expect(ownerPage.locator('#sshkey-requests-table')).toContainText('1');

    await loginAs(adminPage, ADMIN_USERNAME, ADMIN_PASSWORD);
    await adminPage.locator('#nav-sshkeys').click();
    await expect(adminPage.locator('#sshkeys-tab')).toHaveClass(/active/);
    await expect(adminPage.locator('#sshkey-admin-table')).toContainText(OWNER_VIEWER_USERNAME, { timeout: 10000 });

    await adminPage.locator('#sshkey-admin-table tr', { hasText: OWNER_VIEWER_USERNAME }).locator('button[data-reject-id]').click();
    await expect(adminPage.locator('#sshkey-admin-table')).not.toContainText(OWNER_VIEWER_USERNAME, { timeout: 10000 });

    await ownerPage.reload();
    await ownerPage.locator('#nav-sshkeys').click();
    await expect(ownerPage.locator('#sshkey-requests-table')).toContainText('rejected', { timeout: 10000 });
  } finally {
    await ownerPage.close();
    await adminPage.close();
  }
});
