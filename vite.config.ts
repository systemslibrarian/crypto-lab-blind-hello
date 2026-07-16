import { defineConfig } from 'vitest/config';

export default defineConfig({
  base: '/crypto-lab-blind-hello/',
  build: {
    target: 'es2022',
  },
  server: {
    fs: {
      // The HPKE implementation is consumed from the sibling checkout
      // ../crypto-lab-hpke-envelope (the hub) — allow the dev server to read it.
      allow: ['..'],
    },
  },
  test: {
    include: ['src/**/*.test.ts'],
  },
});
