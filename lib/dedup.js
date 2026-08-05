function normalizePathSegment(value) {
  return String(value || '').trim().replace(/^\/+|\/+$/g, '');
}

export function isInDedupeFolder(file, dupesFolder) {
  if (typeof file?.inDedupeFolder === 'boolean') return file.inDedupeFolder;

  const folderName = normalizePathSegment(dupesFolder);
  if (!folderName) return false;

  const firstParent = file?.parentChain?.[0];
  return firstParent?.name === folderName;
}

export function excludeDedupeFolderFiles(files, dupesFolder) {
  const folderName = normalizePathSegment(dupesFolder);
  const rootFolders = files
    .filter((file) => {
      return file.mimeType === 'application/vnd.google-apps.folder'
        && file.parentChain?.length === 0;
    })
    .sort((first, second) => {
      return String(first.createdTime || '').localeCompare(String(second.createdTime || ''))
        || String(first.id).localeCompare(String(second.id));
    });
  const markedRoot = rootFolders.find((file) => file.appProperties?.dedriveRole === 'dupesRoot');
  const namedRoot = rootFolders.find((file) => file.name === folderName);
  const dedupeRootId = markedRoot?.id || namedRoot?.id || null;

  return files.filter((file) => {
    const inDedupeFolder = Boolean(
      dedupeRootId
      && (
        file.id === dedupeRootId
        || file.parentChain?.some((segment) => segment.id === dedupeRootId)
      )
    );
    file.inDedupeFolder = inDedupeFolder;
    return !inDedupeFolder;
  });
}

export function findDuplicates(files) {
  const byMd5 = new Map();

  for (const file of files) {
    if (!file.md5Checksum) continue;
    if (file.mimeType === 'application/vnd.google-apps.folder') continue;
    if (file.mimeType?.startsWith('application/vnd.google-apps.')) continue;

    const group = byMd5.get(file.md5Checksum) || [];
    group.push(file);
    byMd5.set(file.md5Checksum, group);
  }

  const groups = [];
  for (const [md5, groupFiles] of byMd5) {
    if (groupFiles.length < 2) continue;

    const sizes = new Set(groupFiles.map((f) => f.size));
    groups.push({
      md5,
      files: groupFiles,
      uncertain: sizes.size > 1,
      totalSize: groupFiles.reduce((sum, f) => sum + (parseInt(f.size) || 0), 0),
      wastedSize: groupFiles.slice(1).reduce((sum, f) => sum + (parseInt(f.size) || 0), 0),
    });
  }

  groups.sort((a, b) => b.wastedSize - a.wastedSize);
  return groups;
}

export function resolvePaths(files) {
  const byId = new Map();
  for (const f of files) byId.set(f.id, f);

  const chainCache = new Map();

  function getItemChain(fileId, visiting = new Set()) {
    if (chainCache.has(fileId)) return chainCache.get(fileId);
    if (visiting.has(fileId)) return [];

    const file = byId.get(fileId);
    if (!file) return [];

    const nextVisiting = new Set(visiting);
    nextVisiting.add(fileId);
    const parentId = file.parents?.[0];
    const parentChain = parentId && byId.has(parentId)
      ? getItemChain(parentId, nextVisiting)
      : [];
    const chain = [...parentChain, { id: file.id, name: file.name }];
    chainCache.set(fileId, chain);
    return chain;
  }

  for (const f of files) {
    const parentId = f.parents?.[0];
    f.parentChain = parentId && byId.has(parentId)
      ? getItemChain(parentId)
      : [];
    f.path = '/' + [...f.parentChain.map((segment) => segment.name), f.name].join('/');
  }

  return files;
}

export function computeStats(groups) {
  let totalGroups = groups.length;
  let totalFiles = 0;
  let totalWasted = 0;
  let uncertainCount = 0;

  for (const g of groups) {
    totalFiles += g.files.length;
    totalWasted += g.wastedSize;
    if (g.uncertain) uncertainCount++;
  }

  return { totalGroups, totalFiles, totalWasted, uncertainCount };
}
