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

  return { decisions, setDecision, clearDecisions };
}
