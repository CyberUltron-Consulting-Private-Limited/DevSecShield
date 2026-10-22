/**
 * Show a downloaded PDF inside the recorded browser page.
 *
 * Headless Chromium has no PDF viewer, so the spec renders the pages with poppler (lib/evidence.ts
 * pdfToPng) into a local viewer.html and navigates THE SAME page to it: the one video of the spec then
 * contains the UI flow AND the document content, scrolled page by page. The viewer is a static file
 * (no script beyond a page counter), so it adds no network traffic.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import { pathToFileURL } from 'node:url';

import type { Page } from '@playwright/test';

import { escapeHtml } from './evidence';
import { evidencePath } from './paths';

export interface ViewerInput {
  /** `07`, `16`, `91-before`, ... used in the file name viewer-<number>.html */
  number: string;
  title: string;
  subtitle: string;
  /** Page PNGs in order (pdf-pages/...). */
  pages: string[];
}

export function writeViewer(input: ViewerInput): string {
  const dest = evidencePath('pdf-pages', `viewer-${input.number}.html`);
  const total = input.pages.length;
  const sections = input.pages
    .map(
      (png, index) =>
        `<section id="page-${index + 1}"><div class="tag">Page ${index + 1} of ${total}</div>` +
        `<img src="${escapeHtml(path.relative(path.dirname(dest), png))}" alt="${escapeHtml(input.title)} page ${index + 1}"></section>`,
    )
    .join('\n');
  fs.writeFileSync(
    dest,
    `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>${escapeHtml(input.title)}</title>
<style>
  html { scroll-behavior: smooth; }
  body { margin: 0; background: #1e293b; color: #e2e8f0; font: 14px/1.4 Helvetica, Arial, sans-serif; }
  header { position: sticky; top: 0; z-index: 2; padding: 10px 24px; background: #0f172a; border-bottom: 2px solid #3b82f6;
           display: flex; justify-content: space-between; align-items: baseline; gap: 24px; }
  header b { font-size: 17px; } header span { color: #94a3b8; font-size: 12px; }
  #counter { color: #93c5fd; font-weight: 600; white-space: nowrap; }
  main { padding: 18px 0 40px; }
  section { width: min(94vw, 1180px); margin: 0 auto 26px; position: relative; }
  .tag { position: absolute; top: -2px; right: 6px; transform: translateY(-100%); font-size: 12px; color: #94a3b8; }
  img { width: 100%; display: block; background: #fff; box-shadow: 0 6px 28px rgba(0,0,0,.55); }
</style></head><body>
<header><div><b>${escapeHtml(input.title)}</b><br><span>${escapeHtml(input.subtitle)}</span></div><div id="counter">Page 1 of ${total}</div></header>
<main>
${sections}
</main>
<script>
  const counter = document.getElementById('counter');
  const observer = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      if (entry.isIntersecting) counter.textContent = 'Page ' + entry.target.id.slice(5) + ' of ${total}';
    }
  }, { rootMargin: '-45% 0px -45% 0px' });
  document.querySelectorAll('section').forEach((section) => observer.observe(section));
</script>
</body></html>
`,
  );
  return dest;
}

export interface ShowOptions {
  /** Pages (1-based) to align at the top and hand to `onStop` (screenshots). */
  stops: number[];
  onStop?: (pageNumber: number) => Promise<void>;
  /** Pause between scroll steps, in ms (the video is the evidence, so keep it watchable). */
  dwellMs?: number;
  /** Return to the previous (application) page afterwards. Default true. */
  goBack?: boolean;
}

/** Open the viewer in `page`, scroll through the whole document, stop on the requested pages, go back. */
export async function showPdf(page: Page, viewerPath: string, options: ShowOptions): Promise<void> {
  const dwell = options.dwellMs ?? 700;
  await page.goto(pathToFileURL(viewerPath).href, { waitUntil: 'load' });
  await page.waitForFunction(() => [...document.images].every((img) => img.complete && img.naturalWidth > 0));
  await page.waitForTimeout(dwell);

  // Skim the whole document so the video shows it scrolling.
  const height = await page.evaluate(() => document.documentElement.scrollHeight);
  const viewport = page.viewportSize()?.height ?? 900;
  for (let y = 0; y < height - viewport; y += Math.round(viewport * 0.7)) {
    await page.evaluate((top) => window.scrollTo({ top, behavior: 'smooth' }), y);
    await page.waitForTimeout(dwell);
  }

  // Align each requested page at the top and let the spec photograph it.
  for (const n of options.stops) {
    await page.evaluate((id) => {
      document.getElementById(id)?.scrollIntoView({ behavior: 'instant' as ScrollBehavior, block: 'start' });
      window.scrollBy(0, -70); // clear the sticky header
    }, `page-${n}`);
    await page.waitForTimeout(dwell);
    await options.onStop?.(n);
  }
  if (options.goBack !== false) {
    await page.goBack({ waitUntil: 'load' });
    await page.waitForTimeout(300);
  }
}
