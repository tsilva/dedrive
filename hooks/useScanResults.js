import { useState, useCallback } from 'react';

export function useScanResults() {
  const [allFiles, setAllFiles] = useState([]);
  const [dupGroups, setDupGroups] = useState([]);

  const save = useCallback((files, groups) => {
    setAllFiles(files);
    setDupGroups(groups);
  }, []);

  const clear = useCallback(() => {
    setAllFiles([]);
    setDupGroups([]);
  }, []);

  return { allFiles, dupGroups, save, clear };
}
