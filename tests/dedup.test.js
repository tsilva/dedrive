import { describe, expect, it } from 'vitest';
import { excludeDedupeFolderFiles, resolvePaths } from '@/lib/dedup';

const FOLDER = 'application/vnd.google-apps.folder';

describe('structured Drive ancestry', () => {
  it('preserves exact folder names, including slashes and surrounding spaces', () => {
    const files = resolvePaths([
      { id: 'slash-folder', name: 'Invoices / 2026', mimeType: FOLDER, parents: [] },
      { id: 'space-folder', name: '  Final  ', mimeType: FOLDER, parents: ['slash-folder'] },
      { id: 'file', name: 'report.pdf', mimeType: 'application/pdf', parents: ['space-folder'] },
    ]);

    const file = files.find((item) => item.id === 'file');
    expect(file.parentChain).toEqual([
      { id: 'slash-folder', name: 'Invoices / 2026' },
      { id: 'space-folder', name: '  Final  ' },
    ]);
    expect(file.path).toBe('/Invoices / 2026/  Final  /report.pdf');
  });

  it('keeps same-named sibling folders distinct by source ID', () => {
    const files = resolvePaths([
      { id: 'left', name: 'Team A', mimeType: FOLDER, parents: [] },
      { id: 'right', name: 'Team B', mimeType: FOLDER, parents: [] },
      { id: 'left-archive', name: 'Archive', mimeType: FOLDER, parents: ['left'] },
      { id: 'right-archive', name: 'Archive', mimeType: FOLDER, parents: ['right'] },
      { id: 'left-file', name: 'copy.txt', parents: ['left-archive'] },
      { id: 'right-file', name: 'copy.txt', parents: ['right-archive'] },
    ]);

    expect(files.find((item) => item.id === 'left-file').parentChain).toEqual([
      { id: 'left', name: 'Team A' },
      { id: 'left-archive', name: 'Archive' },
    ]);
    expect(files.find((item) => item.id === 'right-file').parentChain).toEqual([
      { id: 'right', name: 'Team B' },
      { id: 'right-archive', name: 'Archive' },
    ]);
  });

  it('excludes only the selected dedrive root and leaves legacy lookalikes untouched', () => {
    const files = resolvePaths([
      {
        id: 'marked-root',
        name: 'Renamed dedrive output',
        mimeType: FOLDER,
        parents: [],
        appProperties: { dedriveRole: 'dupesRoot' },
      },
      { id: 'marked-file', name: 'moved.txt', parents: ['marked-root'] },
      { id: 'legacy-root', name: '_dupes', mimeType: FOLDER, parents: [] },
      { id: 'legacy-file', name: 'keep-visible.txt', parents: ['legacy-root'] },
    ]);

    const visible = excludeDedupeFolderFiles(files, '_dupes');

    expect(visible.map((file) => file.id)).toEqual(['legacy-root', 'legacy-file']);
    expect(files.find((file) => file.id === 'marked-file').inDedupeFolder).toBe(true);
    expect(files.find((file) => file.id === 'legacy-file').inDedupeFolder).toBe(false);
  });
});
