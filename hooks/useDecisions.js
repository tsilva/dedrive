import { useState, useCallback } from 'react';

export function useDecisions() {
  const [decisions, setDecisions] = useState({});

  const setDecision = useCallback((md5, decision) => {
    setDecisions((current) => ({
      ...current,
      [md5]: decision,
    }));
  }, []);

  const clearDecisions = useCallback(() => {
    setDecisions({});
  }, []);

  const removeDecisions = useCallback((md5s) => {
    const removals = new Set(Array.isArray(md5s) ? md5s : [md5s]);
    setDecisions((current) => {
      const next = { ...current };
      removals.forEach((md5) => delete next[md5]);
      return next;
    });
  }, []);

  return { decisions, setDecision, removeDecisions, clearDecisions };
}
