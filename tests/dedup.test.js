import { describe, expect, it } from 'vitest';
import {
  excludeBlacklistedPathFiles,
  excludeDedupeFolderFiles,
  filterOwnedMyDriveTree,
  findDuplicates,
  normalizePathPrefix,
  resolvePaths,
} from '@/lib/dedup';

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

  it('excludes every app-marked cleanup root and leaves unmarked lookalikes untouched', () => {
    const files = resolvePaths([
      {
        id: 'marked-root',
        name: 'Renamed dedrive output',
        mimeType: FOLDER,
        parents: [],
        appProperties: { dedriveRole: 'dupesRoot' },
      },
      { id: 'marked-file', name: 'moved.txt', parents: ['marked-root'] },
      {
        id: 'older-marked-root',
        name: '_dupes',
        mimeType: FOLDER,
        parents: [],
        appProperties: { dedriveRole: 'dupesRoot' },
      },
      { id: 'older-marked-file', name: 'older.txt', parents: ['older-marked-root'] },
      { id: 'legacy-root', name: '_dupes', mimeType: FOLDER, parents: [] },
      { id: 'legacy-file', name: 'keep-visible.txt', parents: ['legacy-root'] },
    ]);

    const visible = excludeDedupeFolderFiles(files, '_dupes');

    expect(visible.map((file) => file.id)).toEqual(['legacy-root', 'legacy-file']);
    expect(files.find((file) => file.id === 'marked-file').inDedupeFolder).toBe(true);
    expect(files.find((file) => file.id === 'older-marked-file').inDedupeFolder).toBe(true);
    expect(files.find((file) => file.id === 'legacy-file').inDedupeFolder).toBe(false);
  });

  it('keeps only items whose complete ancestry is owned', () => {
    const files = [
      { id: 'owned-root-file', name: 'root.txt', ownedByMe: true, parents: ['root-id'] },
      { id: 'owned-folder', name: 'Owned', mimeType: FOLDER, ownedByMe: true, parents: ['root-id'] },
      { id: 'owned-child', name: 'owned.txt', ownedByMe: true, parents: ['owned-folder'] },
      { id: 'shared-folder', name: 'Shared', mimeType: FOLDER, ownedByMe: false, parents: ['root-id'] },
      { id: 'owned-under-shared', name: 'nested.txt', ownedByMe: true, parents: ['shared-folder'] },
      { id: 'shared-file', name: 'shared.txt', ownedByMe: false, parents: ['root-id'] },
      { id: 'parentless-owned', name: 'orphan.txt', ownedByMe: true, parents: [] },
    ];

    expect(filterOwnedMyDriveTree(files, 'root-id').map((file) => file.id)).toEqual([
      'owned-root-file',
      'owned-folder',
      'owned-child',
      'parentless-owned',
    ]);
  });

  it('rejects unresolved, cyclic, and mixed-ownership parent trees', () => {
    const files = [
      { id: 'owned-folder', name: 'Owned', mimeType: FOLDER, ownedByMe: true, parents: ['root-id'] },
      { id: 'shared-folder', name: 'Shared', mimeType: FOLDER, ownedByMe: false, parents: ['root-id'] },
      { id: 'missing-parent', name: 'missing.txt', ownedByMe: true, parents: ['not-listed'] },
      { id: 'cycle-a', name: 'A', mimeType: FOLDER, ownedByMe: true, parents: ['cycle-b'] },
      { id: 'cycle-b', name: 'B', mimeType: FOLDER, ownedByMe: true, parents: ['cycle-a'] },
      {
        id: 'mixed-parents',
        name: 'mixed.txt',
        ownedByMe: true,
        parents: ['owned-folder', 'shared-folder'],
      },
    ];

    expect(filterOwnedMyDriveTree(files, 'root-id').map((file) => file.id)).toEqual(['owned-folder']);
  });
});

describe('blacklisted path prefixes', () => {
  it('normalizes user-entered prefixes', () => {
    expect(normalizePathPrefix('  /Archive/2020/  ')).toBe('/Archive/2020');
    expect(normalizePathPrefix('Archive')).toBe('/Archive');
    expect(normalizePathPrefix('/Archive/*')).toBe('/Archive');
    expect(normalizePathPrefix('/')).toBe('');
    expect(normalizePathPrefix('   ')).toBe('');
    expect(normalizePathPrefix(null)).toBe('');
  });

  it('excludes exact prefixes and descendants without matching sibling name prefixes', () => {
    const files = [
      { id: 'archive', path: '/Archive', name: 'Archive' },
      { id: 'archive-file', path: '/Archive/report.pdf', name: 'report.pdf' },
      { id: 'archive-2026', path: '/Archive2026/report.pdf', name: 'report.pdf' },
      { id: 'photos', path: '/Photos/Backup/img.jpg', name: 'img.jpg' },
      { id: 'keep', path: '/Keep/report.pdf', name: 'report.pdf' },
    ];

    const visible = excludeBlacklistedPathFiles(files, ['/archive', '/Photos/Backup']);
    expect(visible.map((file) => file.id)).toEqual(['archive-2026', 'keep']);
    expect(files.find((file) => file.id === 'archive-file').pathBlacklisted).toBe(true);
    expect(files.find((file) => file.id === 'archive').pathBlacklisted).toBe(true);
    expect(files.find((file) => file.id === 'archive-2026').pathBlacklisted).toBe(false);
  });

  it('ignores empty and duplicate prefixes', () => {
    const files = [
      { id: 'a', path: '/A/file.txt', name: 'file.txt' },
      { id: 'b', path: '/B/file.txt', name: 'file.txt' },
    ];

    const visible = excludeBlacklistedPathFiles(files, ['', '/', 'A', 'a']);
    expect(visible.map((file) => file.id)).toEqual(['b']);
  });

  it('keeps every file when no prefixes are configured', () => {
    const files = [
      { id: 'a', path: '/A/file.txt', name: 'file.txt' },
      { id: 'b', path: '/B/file.txt', name: 'file.txt' },
    ];

    expect(excludeBlacklistedPathFiles(files, []).map((file) => file.id)).toEqual(['a', 'b']);
    expect(excludeBlacklistedPathFiles(files, undefined).map((file) => file.id)).toEqual(['a', 'b']);
  });
});

describe('duplicate review ordering', () => {
  it('sorts files and groups by natural source path with stable ID tie-breakers', () => {
    const files = [
      { id: 'report-zeta', md5Checksum: 'report', name: 'report.pdf', path: '/Projects/Zeta/report.pdf', size: '10' },
      { id: 'notes-10', md5Checksum: 'notes', name: 'notes.txt', path: '/Projects/10/notes.txt', size: '5' },
      { id: 'report-alpha-b', md5Checksum: 'report', name: 'report.pdf', path: '/Projects/Alpha/report.pdf', size: '10' },
      { id: 'archive-b', md5Checksum: 'archive', name: 'copy.txt', path: '/Archive/copy.txt', size: '2' },
      { id: 'notes-2', md5Checksum: 'notes', name: 'notes.txt', path: '/Projects/2/notes.txt', size: '5' },
      { id: 'archive-a', md5Checksum: 'archive', name: 'copy.txt', path: '/Archive/copy.txt', size: '2' },
      { id: 'report-alpha-a', md5Checksum: 'report', name: 'report.pdf', path: '/projects/alpha/report.pdf', size: '10' },
    ];
    const groups = findDuplicates(files);
    const reverseScanGroups = findDuplicates([...files].reverse());
    const summarizeOrder = (orderedGroups) => orderedGroups.map((group) => ({
      md5: group.md5,
      fileIds: group.files.map((file) => file.id),
    }));

    expect(summarizeOrder(reverseScanGroups)).toEqual(summarizeOrder(groups));
    expect(groups.map((group) => group.md5)).toEqual(['archive', 'notes', 'report']);
    expect(groups.find((group) => group.md5 === 'archive').files.map((file) => file.id)).toEqual([
      'archive-a',
      'archive-b',
    ]);
    expect(groups.find((group) => group.md5 === 'notes').files.map((file) => file.id)).toEqual([
      'notes-2',
      'notes-10',
    ]);
    expect(groups.find((group) => group.md5 === 'report').files.map((file) => file.id)).toEqual([
      'report-alpha-b',
      'report-alpha-a',
      'report-zeta',
    ]);
  });
});
