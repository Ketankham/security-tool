"use client";

import { useCallback, useEffect, useRef, useState } from "react";

export interface PollState<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
  refresh: () => void;
}

// Fetch `fn` on mount and then every `intervalMs` while `active` stays true.
// Returns the latest data, keeping the previous value visible during a
// refetch so the UI doesn't flash. Pass active=false to stop polling (e.g.
// once a scan reaches a terminal state).
export function usePoll<T>(
  fn: () => Promise<T>,
  intervalMs: number,
  active = true,
): PollState<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const fnRef = useRef(fn);
  fnRef.current = fn;

  const run = useCallback(async () => {
    try {
      const result = await fnRef.current();
      setData(result);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    const tick = () => {
      if (!cancelled) void run();
    };
    tick();
    if (!active) return;
    const id = setInterval(tick, intervalMs);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [run, intervalMs, active]);

  return { data, error, loading, refresh: run };
}
