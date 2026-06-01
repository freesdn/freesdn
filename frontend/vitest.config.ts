/// <reference types="vitest" />
/**
 * Dedicated Vitest config.
 *
 * Vitest picks this file in preference to the inline `test` block inside
 * `vite.config.ts`. We deliberately don't import `vite.config.ts` here:
 *   1. `vite.config.ts` writes `src/lib/build-info.ts` and shells out to
 *      `npm --version` at module load, which is unwanted noise per test
 *      run and would also fail in CI sandboxes that don't allow exec.
 *   2. Vitest only needs the React plugin and the `@` path alias, both
 *      of which are cheap to declare inline.
 */
import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  test: {
    globals: true,
    environment: 'happy-dom',
    setupFiles: ['./src/test-utils/setup.ts'],
    css: false,
    include: ['src/**/*.{test,spec}.{ts,tsx}'],
    // happy-dom + heavy deps (recharts, react-flow) make cold setup slow
    // on Windows. The default ~5s threshold otherwise trips for tests
    // that pull in the full UI surface. We keep test timeout itself
    // tight (5s) so genuine async hangs still fail fast.
    testTimeout: 5_000,
    hookTimeout: 10_000,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html'],
      exclude: [
        'dist/**',
        'storybook-static/**',
        'playwright-report/**',
        'tests/**',
        'tests-results/**',
        'node_modules/**',
        '**/*.stories.{ts,tsx}',
        '**/*.test.{ts,tsx}',
        '**/__tests__/**',
        'src/lib/api/generated/**',
        'src/lib/build-info.ts',
        'src/test-utils/**',
        'src/test/**',
        'src/vite-env.d.ts',
        'src/main.tsx',
        '**/*.config.{ts,js}',
        'eslint.config.{ts,js,d.ts}',
        'vite.config.{ts,js}',
        'vitest.config.{ts,js}',
      ],
    },
  },
});
