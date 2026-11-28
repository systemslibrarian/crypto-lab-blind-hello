import { expect, test } from '@playwright/test';

test('an empty custom destination clears evidence and blocks a send', async ({ page }) => {
  await page.goto('.');
  const send = page.getByRole('button', { name: 'Send both ClientHellos' });
  const cards = page.locator('.wire-grid .wirecard');
  await send.click();
  await expect(cards).toHaveCount(2);
  await page.locator('#obs-host').selectOption('__custom');
  await expect(send).toBeDisabled();
  await expect(cards).toHaveCount(0);
  await expect(page.locator('.obs-narrator')).toContainText('Enter a custom destination');
  await page.locator('#obs-custom').fill('clinic.example.net');
  await send.click();
  await expect(cards.first().locator('.verdicts')).toContainText('clinic.example.net');
  await page.locator('#obs-custom').fill(' ');
  await expect(send).toBeDisabled();
  await expect(cards).toHaveCount(0);
});
