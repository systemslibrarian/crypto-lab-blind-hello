import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Four rules govern everything here:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The gate this replaces
 *     asked for `reducedMotion: 'reduce'` and then, in the very next line,
 *     pushed `animation: none !important; transition: none !important` through
 *     `addStyleTag` anyway. Overriding from the test bypasses this lab's own
 *     `@media (prefers-reduced-motion: reduce)` block instead of exercising it,
 *     so it could not catch the defect where a reduced-motion path cancels an
 *     animation without restoring its end state — which is a live risk here,
 *     because `.wirecard-body > *` and `.verdicts.reveal` animate in from
 *     `opacity: 0` and that block cancels the animation outright rather than
 *     collapsing its duration. `boot` asks for the preference, asserts it took
 *     effect, `settle` waits for the animations to drain, and `expectNotBlank`
 *     checks the end state actually landed.
 *
 *  2. EVERY STATE IS SCANNED, NOT ONLY THE LAST ONE. The gate this replaces ran
 *     the whole lab — observer, seal, swap attack, both DNS transports, tamper,
 *     stale key, retry, substituted-config attack, GREASE — and then scanned
 *     ONCE, at the end, after every intermediate verdict had been overwritten
 *     by the next one. The alarm tones it built and threw away are the ones this
 *     lab exists to show.
 *
 *  3. `<details>` ARE OPENED BY THEIR SUMMARIES. The old gate set `.open = true`
 *     on every `<details>` from script, so the shut state was never scanned and
 *     the open one was never reached the way a reader reaches it.
 *
 *  4. `violations` IS NOT THE WHOLE ORACLE. See `scan`.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set. This lab is
 * one CSS declaration away from exactly that: every direct child of a
 * `.wirecard-body`, and every `.verdicts.reveal`, carries
 * `animation: step-in .35s ease both`, and `step-in` starts at `opacity: 0`.
 * The reduced-motion block sets `animation: none`, which is safe *here* only
 * because the animation's end state is the element's natural state — remove the
 * animation and the element is simply opaque. Add one `opacity: 0` to the
 * unanimated rule, or make `step-in` end anywhere but the natural value, and
 * every revealed step goes invisible for readers with the preference set. This
 * assertion is what notices.
 *
 * `aria-hidden` subtrees are excluded. The cost of that exclusion is stated
 * plainly: text removed from the accessibility tree AND painted at zero opacity
 * is not checked here.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      if (el.closest('[aria-hidden="true"]')) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert THE LAB'S DEFAULTS rather than assuming them.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page: an emulation that silently did nothing would
 * leave the gate certifying a different rendering than the one it claims to.
 *
 * The default assertions matter for the same reason. Which half of this lab a
 * scan measures is decided entirely by controls that ship in a particular
 * position — the DNS transport radio decides whether the bootstrap panel prints
 * its `chip-alarm` leak verdict or its `chip-ok` opaque one, and `#obs-host`
 * decides which destination every downstream verdict names. If the transport
 * shipped on `doh`, a gate that only clicked "Look up the ECHConfig" would scan
 * the passing tone forever and never the alarm one.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the
  // whole test timeout and reports nothing useful. 20s turns that silent hang
  // into a named failure naming the locator.
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);

  // `index.html` ships only the hero; every panel below it is built by
  // `src/main.ts` into `#app`, so a navigation that resolves proves nothing.
  await expect(page.locator('main.lab-main')).toBeVisible();
  await expect(page.locator('section.panel')).toHaveCount(8);

  // Defaults, asserted:
  //  - the destination select sits on the first preset, so every verdict the
  //    drive produces below names bank.example.com until the drive changes it;
  await expect(page.locator('#obs-host')).toHaveValue('bank.example.com');
  //  - the custom-hostname branch of that fork is not taken;
  await expect(page.locator('#obs-custom')).toBeHidden();
  //  - the DNS lookup travels in cleartext, which is the leaking half;
  await expect(page.locator('#dns-plaintext')).toBeChecked();
  await expect(page.locator('#dns-doh')).not.toBeChecked();
  //  - both recovery controls are locked behind a prerequisite;
  await expect(page.getByRole('button', { name: /swap the outer/i })).toBeDisabled();
  await expect(page.getByRole('button', { name: /retry with the fresh/i })).toBeDisabled();
  //  - and nothing has been computed yet, so the first scan is a scan of the
  //    empty page a visitor actually lands on.
  await expect(page.locator('.wirecard')).toHaveCount(0);
  await expect(page.locator('.hexdump-region')).toHaveCount(0);
  await expect(page.locator('details[open]')).toHaveCount(0);

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this lab is a
 * plausible offender: it prints 16-byte-per-row hex dumps in a monospace font,
 * lays the ECHConfig delivery-channel comparison out as a four-column table,
 * the GREASE comparison as a three-column one, and prints raw hex payload
 * prefixes inline in prose.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide box inside an `overflow-x: auto` wrapper has a huge bounding rect
    // but is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element. That
    // cost a run elsewhere in this fleet, and this lab is full of the same
    // decoy: every `<pre class="hexdump">` is far wider than its viewport at
    // 380px and scrolls sideways inside its own `.hexdump-region`.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    // Prefer an unclipped culprit; fall back to the widest clipped one rather
    // than reporting nothing, so the message always names something to look at.
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 * If it holds no focusable content it needs `tabindex="0"`, so it becomes a
 * focus target arrow keys can then scroll.
 *
 * This lab's packet dumps are the case: `.hexdump-region` is `overflow: auto`
 * around content both wider and taller than its box, and it holds no focusable
 * child at all — every byte in it is a text node or a `<mark>`.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops, so a page with defects in several states needs one full run per
 * defect to enumerate them. The collection pass turns that into a single run.
 * It is a debugging aid only: `A11Y_COLLECT` is never set in CI or in the
 * committed workflow, and a run with it set prints a banner and fails at the
 * end, so a green collection run cannot be mistaken for a green gate.
 */
const COLLECTING = !!process.env.A11Y_COLLECT;
const collected: string[] = [];

function record(entry: string): void {
  collected.push(entry);
  // Printed as it happens, not only at the end: a hard assertion later in the
  // drive would otherwise abort the test before anything collected so far was
  // ever shown.
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`);
}

function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected);
    return;
  }
  try {
    expect(actual, message).toEqual(expected);
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`);
  }
}

/**
 * Fail the test if the collection pass recorded anything.
 *
 * Without this a collection run would end green, and a green collection run is
 * indistinguishable from a green gate — which is the exact confusion the whole
 * exercise exists to remove.
 */
export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([]);
}

/**
 * Scan the page as it currently stands.
 *
 * Six assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - `expectNotBlank` — the reduced-motion end-state check above.
 *  - `violations` — the usual WCAG A/AA rule failures.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically — which matters here because every `.wirecard` is a
 *    `color-mix()` axe declines to resolve, and the wirecards are where the
 *    headline mechanism prints. Everything else in that bucket is a real result
 *    axe simply could not finish — including `aria-prohibited-attr`, which is
 *    where an `aria-label` on a role-less element hides, a defect that never
 *    reaches the violations array at all.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  await expectScrollersReachableSoft(page, label);
  await expectNoHorizontalOverflowSoft(page, label);
}

async function expectScrollersReachableSoft(page: Page, label: string): Promise<void> {
  if (!COLLECTING) return expectScrollersReachable(page, label);
  try {
    await expectScrollersReachable(page, label);
  } catch (e) {
    record(String(e).slice(0, 900));
  }
}

async function expectNoHorizontalOverflowSoft(page: Page, label: string): Promise<void> {
  if (!COLLECTING) return expectNoHorizontalOverflow(page, label);
  try {
    await expectNoHorizontalOverflow(page, label);
  } catch (e) {
    record(String(e).slice(0, 900));
  }
}

/**
 * Drive the lab through every state that renders content, scanning each.
 *
 * Four things shape this drive:
 *
 *  - THE ALARM STATES ARE THE LESSON. This lab is built out of paired verdicts:
 *    the plain ClientHello leaking the destination against the ECH one hiding
 *    it, plaintext DNS against DoH, a swap attack that fails closed against a
 *    substituted-config attack that succeeds and is therefore rendered as
 *    ALARM. `chip-alarm`, `chip-warn`, `chip-ok`, `chip-fact`, `hl-alarm`,
 *    `hl-ok` and `hl-info` are seven distinct ink/surface pairs and each one
 *    only exists in some of those states. All seven are driven, and each is
 *    scanned in the state it appears in rather than in whatever state happened
 *    to survive to the end of the run.
 *
 *  - THE RETIREMENT NOTICES ARE A STATE, not a transition. Every panel here
 *    subscribes to `onLabInputChange` and replaces its output with a
 *    `.stale-note` when the destination or the server key moves under it. That
 *    is a real thing a visitor sees, on its own surface, and the gate this
 *    replaces never rendered one. Both triggers are driven: changing
 *    `#obs-host`, and the "Use a stale key" button, which rotates the server key
 *    and therefore retires every other panel holding a result at once.
 *
 *  - THE LOCKED STATES ARE SCANNED BEFORE THE UNLOCK. "Attack: swap the outer"
 *    and "Recover: retry with the fresh retry_configs" both ship disabled and
 *    stay disabled until a prerequisite runs; `boot` asserts that, and the
 *    disabled rendering is what the first scans measure.
 *
 *  - COMPLETION IS WAITED ON, NEVER TIMED. Every button here is async — real
 *    HPKE seals and opens — so each step waits on the output the lab itself
 *    produces (a wirecard count, a verdict chip, a button re-enabling), not on
 *    a fixed delay.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${theme} / ${s}`);

  await scanAt('first paint, nothing computed');

  await page.locator('a.cl-skip-link').focus();
  await scanAt('skip link focused');

  // ── The observer panel: one wire, two ClientHellos ───────────────────────
  const sendBoth = page.getByRole('button', { name: 'Send both ClientHellos' });
  await sendBoth.click();
  // The lab's own completion signal: both cards fully staged, and the narrator
  // on its closing line. Waiting on the narrator rather than on a delay is what
  // makes this a scan of the finished reveal.
  await expect(page.locator('.wirecard')).toHaveCount(2);
  await expect(page.locator('.wirecard .verdicts')).toHaveCount(2);
  await expect(page.locator('.obs-narrator')).toHaveText(/that field is the whole point/);
  await scanAt('both ClientHellos observed — alarm verdict on the plain one, ok on the ECH one');

  // ── Changing the destination retires the verdicts that named the old one ──
  await page.locator('#obs-host').selectOption('news.example.org');
  await expect(page.locator('.wirecard')).toHaveCount(0);
  await expect(page.locator('.obs-narrator')).toHaveText(/have been retired/);
  await scanAt('destination changed — observer verdicts retired');

  await sendBoth.click();
  await expect(page.locator('.obs-narrator')).toHaveText(/that field is the whole point/);
  await scanAt('observer re-run for the second preset destination');

  // ── The custom-hostname branch of the destination fork ───────────────────
  await page.locator('#obs-host').selectOption('__custom');
  await expect(page.locator('#obs-custom')).toBeVisible();
  // Selecting "custom" does NOT change the hostname, so the previous verdicts
  // are still on screen and still current — an empty text field beside a live
  // result is its own state.
  await expect(page.locator('.wirecard')).toHaveCount(2);
  await scanAt('custom-hostname field revealed, still empty');

  await page.locator('#obs-custom').fill('clinic.internal.example');
  await expect(page.locator('.wirecard')).toHaveCount(0);
  await scanAt('custom destination typed — verdicts retired again');

  await sendBoth.click();
  await expect(page.locator('.obs-narrator')).toHaveText(/that field is the whole point/);
  await scanAt('observer run for a custom destination');

  // ── Inner/outer construction, then the swap attack ───────────────────────
  const swap = page.getByRole('button', { name: /swap the outer/i });
  await page.getByRole('button', { name: 'Build and seal' }).click();
  await expect(page.locator('.stages .stage')).toHaveCount(5);
  await expect(swap).toBeEnabled();
  await scanAt('inner/outer built through the splice proof, swap attack now unlocked');

  await swap.click();
  await expect(page.locator('.chip-ok').filter({ hasText: 'the binding held' })).toBeVisible();
  await scanAt('swap attack ran — AEAD open failed, binding held');

  // ── The bootstrap problem, both transports ───────────────────────────────
  const lookup = page.getByRole('button', { name: 'Look up the ECHConfig' });
  await lookup.click();
  await expect(page.locator('.dns-out .chip-alarm')).toBeVisible();
  await scanAt('plaintext DNS lookup — the name leaked before TLS began');

  await page.locator('#dns-doh').check();
  await lookup.click();
  await expect(page.locator('.dns-out .chip-warn')).toBeVisible();
  await scanAt('encrypted DNS lookup — opaque to the observer, trust moved to the resolver');

  // ── Break it: a tampered config, its recovery, then a key rotation ────────
  const retry = page.getByRole('button', { name: /retry with the fresh/i });
  await page.getByRole('button', { name: /Tamper the ECHConfig/ }).click();
  await expect(retry).toBeEnabled();
  await scanAt('ECHConfig tampered — HPKE open failed, retry_configs offered');

  await retry.click();
  await expect(page.locator('.chip-ok').filter({ hasText: 'recovered' })).toBeVisible();
  await expect(retry).toBeDisabled();
  await scanAt('recovered with retry_configs — control locked again');

  // Rotating the server key is the one action that reaches across panels: the
  // four other subscribers to `onLabInputChange` that are holding a result —
  // observer, inner/outer, DNS, trust — retire it in the same tick, and this
  // panel prints its own warn-toned verdict beside them.
  await page.getByRole('button', { name: /Use a stale key/ }).click();
  await expect(page.locator('.chip-warn').filter({ hasText: 'ECH was not accepted' })).toBeVisible();
  await expect(page.locator('.stale-note').first()).toBeVisible();
  await scanAt('server key rotated — stale-key verdict, and every other panel retired');

  await retry.click();
  await expect(page.locator('.chip-ok').filter({ hasText: 'recovered' })).toBeVisible();
  await scanAt('recovered from the rotation');

  // ── The substituted-config attack: valid crypto, wrong recipient ─────────
  await page.getByRole('button', { name: /substituted-config attack/i }).click();
  await expect(page.locator('.trust-out .chip-alarm')).toBeVisible();
  await scanAt('substituted-config attack — DISCLOSURE, rendered as alarm not success');

  // ── GREASE ───────────────────────────────────────────────────────────────
  await page.getByRole('button', { name: /GREASE client on the wire/ }).click();
  await expect(page.locator('.grease-out table')).toBeVisible();
  await scanAt('GREASE compared field-for-field against a real ECH client');

  // ── Every disclosure, opened the way a reader opens it ───────────────────
  const count = await page.locator('details').count();
  expect(count, 'the intro glossary is the page’s only disclosure').toBe(1);
  for (let i = 0; i < count; i++) {
    const d = page.locator('details').nth(i);
    await d.locator('> summary').click();
    await expect(d).toHaveAttribute('open', '');
    await scanAt(`disclosure ${i + 1} of ${count} open`);
  }
}
