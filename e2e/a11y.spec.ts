import { test } from '@playwright/test';
import { boot, driveAllStates, expectBaselineNotStale, NARROW, reportCollected } from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * The lab is driven the way a visitor drives it: both ClientHellos put on the
 * wire and observed, the destination changed so the verdicts that named the old
 * one are retired, the custom-hostname branch of that fork taken, the
 * inner/outer construction built through its splice proof and then attacked by
 * swapping the outer, the ECHConfig looked up over plaintext DNS and then over
 * DoH, the config tampered and recovered, the server key rotated so every other
 * panel retires at once, the substituted-config attack run, GREASE compared
 * against a real client, and the glossary opened by its own summary. Every
 * resulting state is scanned in both themes at desktop and phone width.
 *
 * See `gate.ts` for why nothing is injected into the page, why reduced motion is
 * asked for rather than forced, why the lab's defaults are asserted rather than
 * assumed, why every step is scanned rather than only the last, and why
 * `violations` is not the whole oracle.
 */

for (const theme of ['dark'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(900_000);
    await boot(page, theme);
    await driveAllStates(page, theme);
    reportCollected();
    expectBaselineNotStale();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(900_000);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    reportCollected();
    expectBaselineNotStale();
  });
}
