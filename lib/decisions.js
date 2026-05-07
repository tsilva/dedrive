export function getDecisionKeepIds(decision) {
  if (!decision || decision.action !== 'keep') return [];
  if (Array.isArray(decision.keepIds)) return decision.keepIds;
  return decision.keep ? [decision.keep] : [];
}

export function countMovableFiles(group, decision) {
  const keepIds = new Set(getDecisionKeepIds(decision));
  if (keepIds.size === 0) return 0;
  return group.files.filter((file) => !keepIds.has(file.id)).length;
}
