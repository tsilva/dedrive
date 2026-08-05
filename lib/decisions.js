export function getDecisionDiscardIds(decision) {
  if (!decision || decision.action === 'skip') return [];
  return Array.isArray(decision.discardIds) ? decision.discardIds : [];
}

export function countMovableFiles(group, decision) {
  const discardIds = new Set(getDecisionDiscardIds(decision));
  if (discardIds.size === 0) return 0;
  return group.files.filter((file) => discardIds.has(file.id)).length;
}
