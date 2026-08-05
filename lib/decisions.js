export function getDecisionDiscardIds(decision) {
  if (!decision || decision.action === 'skip') return [];
  return Array.isArray(decision.discardIds) ? decision.discardIds : [];
}

export function validateDiscardDecision(group, decision) {
  if (!group || !Array.isArray(group.files) || group.files.length === 0) {
    return {
      valid: false,
      discardIds: [],
      error: 'This duplicate group is no longer available. Run a new scan.',
    };
  }

  if (decision?.action === 'skip') {
    return { valid: true, discardIds: [], error: null };
  }

  if (!decision || decision.action !== 'discard' || !Array.isArray(decision.discardIds)) {
    return {
      valid: false,
      discardIds: [],
      error: 'This duplicate group has an invalid review decision. Review it again.',
    };
  }

  const groupIds = new Set(group.files.map((file) => file.id));
  const discardIds = [...new Set(decision.discardIds)];
  if (discardIds.some((id) => !groupIds.has(id))) {
    return {
      valid: false,
      discardIds: [],
      error: 'This duplicate group contains a stale file selection. Review it again.',
    };
  }

  if (discardIds.length >= group.files.length) {
    return {
      valid: false,
      discardIds: [],
      error: 'Keep at least one copy in every duplicate group.',
    };
  }

  return { valid: true, discardIds, error: null };
}

export function countMovableFiles(group, decision) {
  const validation = validateDiscardDecision(group, decision);
  if (!validation.valid) return 0;

  const discardIds = new Set(validation.discardIds);
  if (discardIds.size === 0) return 0;
  return group.files.filter((file) => discardIds.has(file.id)).length;
}
