import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/**
 * Reveal collapsed content and drive every interaction so the dynamic result
 * regions (observer cards, verdict chips, attack outputs) are present in the
 * scanned DOM — what passes is the page in its fullest state.
 */
async function prepare(page: Page): Promise<void> {
  // Collapse the observer panel's staged reveal to instant, matching what
  // motion-sensitive users get, so the scan sees the fully-revealed page.
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addStyleTag({ content: `*,*::before,*::after{animation:none!important;transition:none!important}` });
  await page.evaluate(() => {
    document.querySelectorAll('details').forEach((d) => ((d as HTMLDetailsElement).open = true));
  });

  // headline observer panel — reducedMotion collapses the staged reveal, so
  // the verdicts land immediately; wait for them before scanning.
  await page.getByRole('button', { name: 'Send both ClientHellos' }).click();
  await expect(page.locator('.wirecard')).toHaveCount(2);
  await expect(page.locator('.wirecard .verdicts')).toHaveCount(2);

  // inner/outer construction + swap attack
  await page.getByRole('button', { name: 'Build and seal' }).click();
  const swap = page.getByRole('button', { name: /swap the outer/i });
  await expect(swap).toBeEnabled();
  await swap.click();

  // DNS bootstrap: plaintext, then DoH re-run
  await page.getByRole('button', { name: 'Look up the ECHConfig' }).click();
  await page.locator('#dns-doh').check();
  await page.getByRole('button', { name: 'Look up the ECHConfig' }).click();

  // break-it: tamper, then stale + retry
  await page.getByRole('button', { name: /Tamper the ECHConfig/ }).click();
  await page.getByRole('button', { name: /Use a stale key/ }).click();
  const retry = page.getByRole('button', { name: /retry with the fresh/i });
  await expect(retry).toBeEnabled();
  await retry.click();

  // trust / substituted-config attack
  await page.getByRole('button', { name: /substituted-config attack/i }).click();
  await expect(page.locator('.trust-out .chip-alarm')).toBeVisible();

  // GREASE comparison
  await page.getByRole('button', { name: /GREASE client on the wire/ }).click();
  await expect(page.locator('.grease-out table')).toBeVisible();

  await page.waitForTimeout(400);
}

async function scan(page: Page): Promise<void> {
  const { violations } = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  expect(
    violations.map((v) => ({ id: v.id, impact: v.impact, nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5) })),
  ).toEqual([]);
}

test('no WCAG A/AA violations — dark theme', async ({ page }) => {
  await page.goto('.');
  await prepare(page);
  await scan(page);
});

test('no WCAG A/AA violations — light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await prepare(page);
  await scan(page);
});
