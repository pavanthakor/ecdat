/**
 * One small loader for the screens' own requests (fixes, scanners, compare).
 *
 * These are secondary to the scan view, so a failure stays LOCAL to the screen
 * that asked: a 404 from `/fixes` must never blank the inventory, and it must
 * never be rendered as "no fixes" either -- `error` is a third state beside
 * "loaded" and "loading", and every screen renders it as such.
 */
import { useCallback, useEffect, useRef, useState } from "react";

export interface Remote<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
  reload: () => void;
}

export function useRemote<T>(key: string | null, load: () => Promise<T>): Remote<T> {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(key !== null);
  const [error, setError] = useState<string | null>(null);
  const [nonce, setNonce] = useState(0);
  const loader = useRef(load);
  loader.current = load;

  useEffect(() => {
    if (key === null) {
      setData(null);
      setLoading(false);
      setError(null);
      return;
    }
    let live = true;
    setLoading(true);
    setError(null);
    loader
      .current()
      .then((value) => {
        if (live) setData(value);
      })
      .catch((cause: unknown) => {
        if (live) {
          setData(null);
          setError(cause instanceof Error ? cause.message : String(cause));
        }
      })
      .finally(() => {
        if (live) setLoading(false);
      });
    return () => {
      live = false;
    };
  }, [key, nonce]);

  const reload = useCallback(() => setNonce((n) => n + 1), []);
  return { data, loading, error, reload };
}
