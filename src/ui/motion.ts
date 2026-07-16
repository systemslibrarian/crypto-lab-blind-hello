/**
 * Purposeful-motion helpers. Every pause here is tied to a reveal step of a
 * mechanism the learner asked to run — never idle/decorative. Under
 * prefers-reduced-motion (or Playwright's forced-reduced-motion), every pause
 * collapses to zero, so the a11y gate and motion-sensitive users get the full
 * content at once with no timing.
 */
export function prefersReducedMotion(): boolean {
  return typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches;
}

export function pause(ms: number): Promise<void> {
  if (prefersReducedMotion()) return Promise.resolve();
  return new Promise((resolve) => setTimeout(resolve, ms));
}
