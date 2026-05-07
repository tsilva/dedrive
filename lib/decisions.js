export function getDecisionKeepIds(decision) {
  if (!decision || decision.action !== 'keep') return [];
  if (Array.isArray(decision.keepIds)) return decision.keepIds;
  return decision.keep ? [decision.keep] : [];
}

export function getDecisionDiscardIds(group, decision) {
  if (!decision || decision.action === 'skip') return [];

  if (Array.isArray(decision.discardIds)) {
    return decision.discardIds;
  }

  // Backward compatibility for in-memory decisions created before discard mode.
  const keepIds = new Set(getDecisionKeepIds(decision));
  if (keepIds.size === 0) return [];
  return group.files
    .filter((file) => !keepIds.has(file.id))
    .map((file) => file.id);
}

export function countMovableFiles(group, decision) {
  const discardIds = new Set(getDecisionDiscardIds(group, decision));
  if (discardIds.size === 0) return 0;
  return group.files.filter((file) => discardIds.has(file.id)).length;
}
