import { defineConfig, devices } from '@playwright/test';

/**
 * Playwright config for Storybook visual regression tests.
 *
 * Strategy:
 * - `npm run build-storybook` produces `storybook-static/`
 * - `webServer` boots a local static server (`http-server`) on port 6006
 * - `tests/visual/storybook.spec.ts` fetches `/index.json`, iterates stories,
 *   navigates to `/iframe.html?id=<story-id>` and screenshots each.
 *
 * First run generates baselines under `tests/visual/__snapshots__/`. Subsequent
 * runs diff against them. To accept new snapshots, run `npm run test:visual:update`.
 */
const PORT = Number(process.env.STORYBOOK_PORT ?? 6006);

export default defineConfig({
  testDir: './tests/visual',
  // Each test is a single page navigation + screenshot; allow up to 30s.
  timeout: 30_000,
  expect: {
    // Allow tiny anti-aliasing / sub-pixel noise without failing the test.
    toHaveScreenshot: {
      maxDiffPixels: 100,
      // Keep snapshot path stable across OSes, no `-darwin`/`-linux` suffixes.
      // CI runs on Linux so baselines should be generated there for production use.
    },
  },
  // Snapshots live next to the spec, in __snapshots__/.
  snapshotPathTemplate: '{testDir}/__snapshots__/{testFilePath}/{arg}{ext}',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: 0,
  // Single chromium project, chromium is the canonical baseline for visual diffs.
  projects: [
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
        viewport: { width: 1280, height: 800 },
        // Disable animations & reduce flake from fade/transition transitions.
        // (Storybook stories should be static visual snapshots.)
        deviceScaleFactor: 1,
      },
    },
  ],
  reporter: process.env.CI ? [['github'], ['html', { open: 'never' }]] : [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    // Reduce flake: wait for network idle on each goto (we override per-test too).
    trace: 'retain-on-failure',
  },
  webServer: {
    // We assume `storybook-static/` already exists. CI builds it explicitly in a
    // prior step; locally, run `npm run build-storybook` once before `test:visual`.
    // (Avoids slow rebuild on every `test:visual` invocation.)
    command: `npx http-server storybook-static -p ${PORT} -s -c-1 --cors`,
    url: `http://127.0.0.1:${PORT}/index.json`,
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
    stdout: 'ignore',
    stderr: 'pipe',
  },
});
