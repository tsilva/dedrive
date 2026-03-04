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

  const pathCache = new Map();

  function getPath(fileId) {
    if (pathCache.has(fileId)) return pathCache.get(fileId);

    const file = byId.get(fileId);
    if (!file) {
      pathCache.set(fileId, '');
      return '';
    }

    const parentId = file.parents?.[0];
    if (!parentId || !byId.has(parentId)) {
      const path = '/' + file.name;
      pathCache.set(fileId, path);
      return path;
    }

    const parentPath = getPath(parentId);
    const path = parentPath + '/' + file.name;
    pathCache.set(fileId, path);
    return path;
  }

  for (const f of files) {
    f.path = getPath(f.id);
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
