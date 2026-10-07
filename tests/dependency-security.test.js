import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

function pdfBytes(openAction = '') {
  return new TextEncoder().encode(`%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R ${openAction ? '/OpenAction 4 0 R' : ''} >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj
${openAction ? `4 0 obj
<< /S /JavaScript /JS (${openAction}) >>
endobj` : ''}
trailer
<< /Root 1 0 R >>
%%EOF`);
}

describe('dependency security boundaries', () => {
  it('keeps every alerted dependency family above its patched floor', () => {
    const lock = readFileSync(resolve(process.cwd(), 'pnpm-lock.yaml'), 'utf8');

    for (const [family, floor] of [['pdfjs-dist', [6, 2, 108]], ['postcss', [8, 5, 23]], ['nanoid', [3, 3, 18]]]) {
      const versions = [...lock.matchAll(new RegExp(`^  ${family}@([^:]+):`, 'gm'))].map((match) => match[1].split('.').map(Number));
      expect(versions.length).toBeGreaterThan(0);
      for (const version of versions) {
        const firstDifference = version.findIndex((part, index) => part !== floor[index]);
        expect(firstDifference === -1 || version[firstDifference] > floor[firstDifference]).toBe(true);
      }
    }
  });

  it('loads a legitimate PDF with dynamic evaluation disabled', async () => {
    const pdfjs = await import('pdfjs-dist/legacy/build/pdf.mjs');
    const task = pdfjs.getDocument({ data: pdfBytes(), isEvalSupported: false });
    const document = await task.promise;

    expect(document.numPages).toBe(1);
    await expect(document.getPage(1)).resolves.toBeDefined();
    await task.destroy();
  });

  it('does not execute a hostile PDF JavaScript action', async () => {
    globalThis.__dedrivePdfExploit = false;
    const pdfjs = await import('pdfjs-dist/legacy/build/pdf.mjs');
    const task = pdfjs.getDocument({
      data: pdfBytes('globalThis.__dedrivePdfExploit = true'),
      isEvalSupported: false,
    });
    const document = await task.promise;

    await document.getPage(1);
    expect(globalThis.__dedrivePdfExploit).toBe(false);
    await task.destroy();
    delete globalThis.__dedrivePdfExploit;
  });
});
