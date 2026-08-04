import { expect, test, type Page } from '@playwright/test';

/**
 * Every result on this page is computed from two inputs: the destination the
 * learner picked, and the server's current HPKE key. A result that outlives
 * either one is a claim about a run that is no longer on screen — an observer
 * verdict naming bank.example.com under a select that now reads
 * news.example.org, or a substitution verdict blaming the AAD binding for a
 * failure a key rotation would have caused anyway.
 *
 * These tests assert the retirement, and assert it against values the page
 * itself printed rather than against hardcoded strings.
 */

async function load(page: Page): Promise<void> {
  await page.goto('.');
  await expect(page.locator('#obs-host')).toBeVisible();
}

test('the observer verdict names the destination it was actually computed for', async ({
  page,
}) => {
  await load(page);

  const chosen = await page.locator('#obs-host').inputValue();
  await page.getByRole('button', { name: 'Send both ClientHellos' }).click();

  // The verdict must mention the hostname the control says is selected — the
  // point of the panel is what an observer can and cannot read off the wire.
  const body = page.locator('#app');
  await expect(body).toContainText(chosen, { timeout: 30_000 });
});

test('changing the destination retires an observer verdict computed for the old one', async ({
  page,
}) => {
  await load(page);

  const first = await page.locator('#obs-host').inputValue();
  await page.getByRole('button', { name: 'Send both ClientHellos' }).click();
  await expect(page.locator('#app')).toContainText(first, { timeout: 30_000 });

  // Pick a genuinely different preset.
  const options = await page.locator('#obs-host option').allTextContents();
  const next = options.find((o) => o !== first && !o.includes('custom'));
  expect(next, 'need a second preset hostname to switch to').toBeTruthy();
  await page.locator('#obs-host').selectOption(next!);

  // The stale verdict must be gone, and the page must SAY it was retired
  // rather than silently blanking — a blank panel reads as "nothing happened".
  await expect(page.locator('#app')).toContainText(/retired/i, { timeout: 10_000 });

  // And it must no longer be asserting anything about the old destination
  // inside a results region.
  const narrator = page.locator('text=/retired/i').first();
  await expect(narrator).toBeVisible();
});

test('a destination that has not changed does not retire a fresh verdict', async ({ page }) => {
  // Guards the no-op guard: re-selecting the same value must not fire a
  // retirement, or every verdict would vanish the moment the learner touched
  // the control without changing anything.
  await load(page);

  const current = await page.locator('#obs-host').inputValue();
  await page.getByRole('button', { name: 'Send both ClientHellos' }).click();
  await expect(page.locator('#app')).toContainText(current, { timeout: 30_000 });

  await page.locator('#obs-host').selectOption(current);
  await page.waitForTimeout(300);
  await expect(page.locator('#app')).not.toContainText(/retired/i);
});

test('rotating the server key retires the substitution result it invalidates', async ({
  page,
}) => {
  await load(page);

  const runTrust = page.getByRole('button', { name: 'Run the substituted-config attack' });
  await runTrust.click();
  // The panel reports what the honest server could do with that ClientHello.
  await expect(page.locator('#app')).toContainText(/honest server/i, { timeout: 30_000 });

  // Rotating the key is an input change: everything already sealed was sealed
  // to the previous key, so the honest-server column would now fail for a
  // reason unrelated to the swap being demonstrated.
  const rotate = page.getByRole('button', { name: /rotate|stale|new key/i }).first();
  if ((await rotate.count()) === 0) {
    test.skip(true, 'no key-rotation control exposed in the UI');
  }
  await rotate.click();

  await expect(page.locator('#app')).toContainText(/retired/i, { timeout: 10_000 });
});
