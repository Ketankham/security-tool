"use client";

import { useEffect, useState } from "react";
import { api } from "./api";
import type { Whoami } from "./types";

// Who is signed in, and which active tools this deployment offers.
//
// The identity comes from the sign-in proxy in front of the API, so the page
// must keep working when it is absent: any failure (old API without /whoami,
// 401, network) yields `whoami: null`, never an error the UI has to show.
// The result is shared by the top bar and the pages so /whoami is asked once
// per page load.

let cached: Promise<Whoami | null> | null = null;

function load(): Promise<Whoami | null> {
  if (!cached) {
    cached = api.whoami().catch(() => null);
  }
  return cached;
}

/** Forget the cached identity (e.g. after a 401/409 hinting it went stale). */
export function resetWhoami(): void {
  cached = null;
}

export function useWhoami(): { whoami: Whoami | null; loading: boolean } {
  const [state, setState] = useState<{ whoami: Whoami | null; loading: boolean }>({
    whoami: null,
    loading: true,
  });
  useEffect(() => {
    let alive = true;
    void load().then((w) => {
      if (!alive) return;
      // A failed lookup must not stay cached forever.
      if (w === null) resetWhoami();
      setState({ whoami: w, loading: false });
    });
    return () => {
      alive = false;
    };
  }, []);
  return state;
}
