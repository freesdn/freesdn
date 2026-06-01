import { test, expect, type Page } from '@playwright/test';

/**
 * Storybook visual regression suite.
 *
 * On startup we fetch `/index.json` (Storybook 7+ on-disk index format) and
 * derive a list of story IDs to snapshot. Stories can opt out by adding the
 * `skip-visual` tag at the meta or story level, useful for fixed-position
 * overlays that don't render meaningfully at viewport scale.
 *
 * Filtering:
 *   STORIES=primitives*       → only stories whose id starts with that
 *   STORIES=foo,bar           → only those exact ids
 *   SKIP_TAGS=skip-visual,wip → tags that exclude a story (default: skip-visual)
 *
 * First run: baselines are generated under tests/visual/__snapshots__/, this
 * is NOT a failure. Commit those baselines so subsequent runs have something
 * to diff against.
 */

interface StoryEntry {
  id: string;
  type: 'story' | 'docs';
  title: string;
  name: string;
  tags?: string[];
}

interface StorybookIndex {
  v: number;
  entries: Record<string, StoryEntry>;
}

const SKIP_TAGS = (process.env.SKIP_TAGS ?? 'skip-visual').split(',').map((s) => s.trim()).filter(Boolean);
const STORIES_FILTER = (process.env.STORIES ?? '').trim();

function matchesFilter(id: string): boolean {
  if (!STORIES_FILTER) return true;
  const filters = STORIES_FILTER.split(',').map((s) => s.trim()).filter(Boolean);
  return filters.some((f) => {
    if (f.endsWith('*')) return id.startsWith(f.slice(0, -1));
    return id === f;
  });
}

async function loadStories(page: Page): Promise<StoryEntry[]> {
  const res = await page.request.get('/index.json');
  if (!res.ok()) {
    throw new Error(`Failed to fetch /index.json: HTTP ${res.status()}. Did Storybook build?`);
  }
  const index = (await res.json()) as StorybookIndex;
  const all = Object.values(index.entries).filter((e) => e.type === 'story');
  const skipped: { id: string; reason: string }[] = [];
  const selected = all.filter((s) => {
    if (!matchesFilter(s.id)) {
      skipped.push({ id: s.id, reason: 'STORIES filter' });
      return false;
    }
    const tags = s.tags ?? [];
    const blocking = tags.find((t) => SKIP_TAGS.includes(t));
    if (blocking) {
      skipped.push({ id: s.id, reason: `tag:${blocking}` });
      return false;
    }
    return true;
  });
  // eslint-disable-next-line no-console
  console.log(
    `[visual] ${selected.length}/${all.length} stories selected for snapshot (${skipped.length} skipped). ` +
      `First-run will GENERATE baselines (not a failure).`,
  );
  if (skipped.length) {
    // eslint-disable-next-line no-console
    console.log(`[visual] skipped: ${skipped.slice(0, 10).map((s) => `${s.id}(${s.reason})`).join(', ')}${skipped.length > 10 ? ` ...+${skipped.length - 10}` : ''}`);
  }
  return selected;
}

// We have to discover stories before declaring tests. Playwright supports this
// pattern via test.describe.parallel with a top-level await using a request
// context. Since `defineConfig` doesn't run async work for us, we do it inline:
// fetch index.json once via Node fetch using the configured baseURL.
async function fetchIndex(): Promise<StoryEntry[]> {
  const port = process.env.STORYBOOK_PORT ?? '6006';
  const url = `http://127.0.0.1:${port}/index.json`;
  // Retry briefly while webServer warms up.
  let lastErr: unknown = null;
  for (let i = 0; i < 30; i++) {
    try {
      const res = await fetch(url);
      if (res.ok) {
        const json = (await res.json()) as StorybookIndex;
        return Object.values(json.entries).filter((e) => e.type === 'story');
      }
      lastErr = new Error(`HTTP ${res.status}`);
    } catch (e) {
      lastErr = e;
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error(`Could not fetch ${url} after 30s: ${String(lastErr)}`);
}

const allStories = await fetchIndex();
const visualStories = allStories.filter((s) => {
  if (!matchesFilter(s.id)) return false;
  const tags = s.tags ?? [];
  return !tags.some((t) => SKIP_TAGS.includes(t));
});

// Print summary once on cold start.
// eslint-disable-next-line no-console
console.log(
  `[visual] discovered ${allStories.length} total stories, ${visualStories.length} after filter/skip-tag. ` +
    `Run STORIES=<pattern> to narrow, SKIP_TAGS=<csv> to override skip list.`,
);

if (visualStories.length === 0) {
  test('no stories matched filter', () => {
    throw new Error(
      `No stories matched. STORIES=${STORIES_FILTER || '(none)'} SKIP_TAGS=${SKIP_TAGS.join(',')}`,
    );
  });
}

for (const story of visualStories) {
  test(`visual: ${story.id}`, async ({ page }) => {
    // Navigate to Storybook's headless story iframe.
    const url = `/iframe.html?id=${encodeURIComponent(story.id)}&viewMode=story`;
    await page.goto(url, { waitUntil: 'load' });

    // Wait for fonts & any in-flight network to settle.
    await page.evaluate(() => document.fonts?.ready);
    // Disable CSS animations / transitions / caret blink to remove flake.
    await page.addStyleTag({
      content: `
        *, *::before, *::after {
          animation-duration: 0s !important;
          animation-delay: 0s !important;
          transition-duration: 0s !important;
          transition-delay: 0s !important;
          caret-color: transparent !important;
        }
      `,
    });
    // Give react-query / framer-motion a tick to commit the final frame.
    await page.waitForLoadState('networkidle').catch(() => {/* ok if no idle */});
    await page.waitForTimeout(200);

    // Snapshot the full page (Storybook iframe = just the story content).
    // Use the story id as the snapshot filename for stability.
    await expect(page).toHaveScreenshot(`${story.id}.png`, {
      fullPage: true,
      // animations are disabled by us above; this is belt-and-suspenders.
      animations: 'disabled',
      caret: 'hide',
    });
  });
}
