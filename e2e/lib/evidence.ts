/**
 * Evidence helpers: save a download, read a PDF with poppler, render its pages, build a contact sheet.
 *
 * Everything shells out to poppler (pdfinfo / pdftotext / pdffonts / pdftoppm) through lib/exec.ts, never
 * through a shell. Text assertions use `pdftotext -raw` (content-stream order, so a wrapped table cell stays
 * contiguous); `-layout` text is saved as human-readable evidence.
 */
import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';

import { expect, type Download } from '@playwright/test';

import { run } from './exec';
import { evidencePath } from './paths';

export interface SavedDownload {
  path: string;
  bytes: number;
  sha256: string;
  suggestedFilename: string;
}

export function sha256File(file: string): string {
  return createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

/** Save a Playwright download under downloads/<destName> and describe it. */
export async function saveDownload(download: Download, destName: string): Promise<SavedDownload> {
  const dest = evidencePath('downloads', destName);
  await download.saveAs(dest);
  const failure = await download.failure();
  if (failure) throw new Error(`download of ${download.suggestedFilename()} failed: ${failure}`);
  const sha256 = sha256File(dest);
  fs.writeFileSync(`${dest}.sha256`, `${sha256}  ${destName}\n`);
  return { path: dest, bytes: fs.statSync(dest).size, sha256, suggestedFilename: download.suggestedFilename() };
}

export interface PdfInfo {
  raw: string;
  pages: number;
  title: string;
  subject: string;
  keywords: string;
  author: string;
  creator: string;
  pageWidth: number;
  pageHeight: number;
  orientation: 'portrait' | 'landscape';
  fileSize: number;
  magicOk: boolean;
}

function field(raw: string, name: string): string {
  const match = new RegExp(`^${name}:\\s*(.*)$`, 'm').exec(raw);
  return match ? match[1].trim() : '';
}

export function pdfInfo(file: string): PdfInfo {
  const raw = run('pdfinfo', [file]).stdout;
  const size = /^Page size:\s*([\d.]+) x ([\d.]+) pts/m.exec(raw);
  const width = size ? Number(size[1]) : 0;
  const height = size ? Number(size[2]) : 0;
  const head = fs.readFileSync(file).subarray(0, 5).toString('latin1');
  return {
    raw,
    pages: Number(field(raw, 'Pages')) || 0,
    title: field(raw, 'Title'),
    subject: field(raw, 'Subject'),
    keywords: field(raw, 'Keywords'),
    author: field(raw, 'Author'),
    creator: field(raw, 'Creator'),
    pageWidth: width,
    pageHeight: height,
    orientation: width > height ? 'landscape' : 'portrait',
    fileSize: fs.statSync(file).size,
    magicOk: head === '%PDF-',
  };
}

/** Whole-document text: `raw` is content-stream order (assertions), `layout` keeps the page geometry (evidence). */
export function pdfText(file: string, mode: 'raw' | 'layout' = 'raw'): string {
  return run('pdftotext', [mode === 'raw' ? '-raw' : '-layout', '-enc', 'UTF-8', file, '-']).stdout;
}

/** One entry per page (pdftotext separates pages with a form feed). */
export function pdfPageTexts(file: string): string[] {
  const pages = pdfText(file, 'raw').split('\f');
  if (pages.length > 1 && pages[pages.length - 1].trim() === '') pages.pop();
  return pages;
}

export interface PdfFont {
  name: string;
  type: string;
  encoding: string;
  embedded: boolean;
}

export function pdfFonts(file: string): { raw: string; fonts: PdfFont[] } {
  const raw = run('pdffonts', [file]).stdout;
  const fonts = raw
    .split('\n')
    .slice(2)
    .filter((line) => line.trim())
    .map((line) => {
      const cols = line.trim().split(/\s+/);
      return {
        name: cols[0],
        type: cols.slice(1, -6).join(' '),
        encoding: cols[cols.length - 6] ?? '',
        embedded: cols[cols.length - 5] === 'yes',
      };
    });
  return { raw, fonts };
}

/**
 * Render every page to pdf-pages/<prefix>-pNN.png (default 130 dpi, readable in a 1440x900 video).
 * Returns the PNG paths in page order.
 */
export function pdfToPng(file: string, prefix: string, dpi = 130, firstPageOnly = false): string[] {
  const dir = path.dirname(evidencePath('pdf-pages', `${prefix}.keep`));
  const stem = path.join(dir, `.render-${prefix}`);
  const range = firstPageOnly ? ['-f', '1', '-l', '1'] : [];
  run('pdftoppm', ['-r', String(dpi), ...range, '-png', file, stem], { timeoutMs: 180_000 });
  const produced = fs
    .readdirSync(dir)
    .filter((name) => name.startsWith(`.render-${prefix}-`) && name.endsWith('.png'))
    .map((name) => ({ name, page: Number(/-(\d+)\.png$/.exec(name)?.[1]) }))
    .sort((a, b) => a.page - b.page);
  return produced.map(({ name, page }) => {
    const dest = path.join(dir, `${prefix}-p${String(page).padStart(2, '0')}.png`);
    fs.renameSync(path.join(dir, name), dest);
    return dest;
  });
}

export interface SheetCell {
  src: string; // image path
  caption: string;
}

/** A static HTML grid of page images (style-parity evidence); returns the HTML path. */
export function contactSheet(
  cells: SheetCell[],
  destName: string,
  options: { title: string; subtitle?: string; columns?: number } = { title: 'Contact sheet' },
): string {
  const columns = options.columns ?? 4;
  const dest = evidencePath('pdf-pages', destName);
  const items = cells
    .map(
      (cell) => `<figure><img src="${path.relative(path.dirname(dest), cell.src)}" alt="">` +
        `<figcaption>${escapeHtml(cell.caption)}</figcaption></figure>`,
    )
    .join('\n');
  fs.writeFileSync(
    dest,
    `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>${escapeHtml(options.title)}</title>
<style>
  body { margin: 0; padding: 18px 22px; font: 14px/1.4 Helvetica, Arial, sans-serif; background: #0f172a; color: #e2e8f0; }
  h1 { font-size: 20px; margin: 0 0 4px; } p { margin: 0 0 14px; color: #94a3b8; }
  .grid { display: grid; grid-template-columns: repeat(${columns}, 1fr); gap: 14px; }
  figure { margin: 0; background: #1e293b; border: 1px solid #334155; border-radius: 6px; padding: 8px; }
  img { width: 100%; height: auto; display: block; background: #fff; }
  figcaption { margin-top: 6px; font-size: 12px; color: #cbd5e1; word-break: break-word; }
</style></head><body>
<h1>${escapeHtml(options.title)}</h1><p>${escapeHtml(options.subtitle ?? '')}</p>
<div class="grid">
${items}
</div></body></html>
`,
  );
  return dest;
}

export function escapeHtml(text: string): string {
  return text.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] as string);
}

export interface AssertPdfOptions {
  minPages: number;
  maxPages?: number;
  titleIncludes?: string;
  orientation?: 'portrait' | 'landscape';
  minBytes?: number;
}

/** Magic number, size, page count, title and orientation: the first things any deliverable must satisfy. */
export function assertPdf(file: string, options: AssertPdfOptions): PdfInfo {
  const info = pdfInfo(file);
  expect(info.magicOk, `${path.basename(file)} must start with %PDF-`).toBe(true);
  expect(info.fileSize, 'PDF size').toBeGreaterThan(options.minBytes ?? 3 * 1024);
  expect(info.pages, 'PDF page count').toBeGreaterThanOrEqual(options.minPages);
  if (options.maxPages !== undefined) expect(info.pages, 'PDF page count (max)').toBeLessThanOrEqual(options.maxPages);
  expect(info.title, 'PDF Title metadata is set').not.toBe('');
  if (options.titleIncludes) expect(info.title).toContain(options.titleIncludes);
  if (options.orientation) expect(info.orientation, 'first-page orientation').toBe(options.orientation);
  return info;
}

/** Write a text or JSON log under logs/. Returns the path. */
export function writeLog(name: string, content: string | object): string {
  const dest = evidencePath('logs', name);
  fs.writeFileSync(dest, typeof content === 'string' ? content : `${JSON.stringify(content, null, 2)}\n`);
  return dest;
}

/** Everything the evidence collector wants for one PDF: pdfinfo / pdftotext / pdffonts logs and the page PNGs. */
export function recordPdfEvidence(
  file: string,
  number: string,
  slug: string,
): { info: PdfInfo; raw: string; pages: string[]; fonts: PdfFont[]; png: string[] } {
  const info = pdfInfo(file);
  writeLog(`${number}-pdfinfo.txt`, info.raw);
  const raw = pdfText(file, 'raw');
  writeLog(`${number}-pdftotext.txt`, pdfText(file, 'layout'));
  writeLog(`${number}-pdftotext-raw.txt`, raw);
  const { raw: fontsRaw, fonts } = pdfFonts(file);
  writeLog(`${number}-pdffonts.txt`, fontsRaw);
  const png = pdfToPng(file, `${number}-${slug}`);
  return { info, raw, pages: pdfPageTexts(file), fonts, png };
}
