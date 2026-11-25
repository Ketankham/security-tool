"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { ApiError, api } from "@/lib/api";
import { toolLabel } from "@/lib/activeTools";
import type { ScanAuthorisation } from "@/lib/types";

// The "I'm authorised" record behind a scan that used active tools: who
// confirmed it, when, for which client, and the exact wording they accepted.
// A scan without active tools has no record (404) and this renders nothing.

export function AuthorisationCard({ scanId }: { scanId: string }) {
  const [auth, setAuth] = useState<ScanAuthorisation | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    setAuth(null);
    setError(null);
    api
      .getScanAuthorisation(scanId)
      .then((a) => {
        if (alive) setAuth(a);
      })
      .catch((e) => {
        if (!alive) return;
        // 404 = "this scan used no active tools": nothing to show.
        if (e instanceof ApiError && e.status === 404) return;
        setError(e instanceof ApiError ? e.detail : String(e));
      });
    return () => {
      alive = false;
    };
  }, [scanId]);

  if (error) {
    return (
      <div className="notice" style={{ marginTop: 16 }}>
        Could not load the authorisation record for this scan: {error}
      </div>
    );
  }
  if (!auth) return null;

  const when = new Date(auth.accepted_at);
  const whenText = Number.isNaN(when.getTime()) ? auth.accepted_at : when.toLocaleString();

  return (
    <div className="card" style={{ marginTop: 16 }}>
      <h2>Authorisation for active tools</h2>
      <ul style={{ margin: 0, paddingLeft: 18, lineHeight: 1.7 }}>
        <li>
          Confirmed by <strong>{auth.username}</strong> on {whenText}
        </li>
        <li>
          Client: <strong>{auth.client_name}</strong> · target <span className="mono">{auth.target_name}</span>{" "}
          · {auth.target_environment === "staging" ? "staging" : "production"}
        </li>
        <li>
          Tools: {auth.tools.length ? auth.tools.map(toolLabel).join(", ") : "none"}
          {auth.all_ports_confirmed && " (all-ports confirmation ticked)"}
        </li>
        {auth.carried_over_from_scan_id && (
          <li>
            Re-confirmed for a retry of{" "}
            <Link href={`/scans/${auth.carried_over_from_scan_id}`} className="mono">
              scan {auth.carried_over_from_scan_id.slice(0, 8)}
            </Link>
          </li>
        )}
      </ul>
      <h3 style={{ marginTop: 12 }}>Statement accepted (version {auth.statement_version})</h3>
      <blockquote
        style={{
          margin: "4px 0 0",
          padding: "8px 12px",
          borderLeft: "3px solid var(--accent-dim)",
          background: "var(--bg)",
          borderRadius: "var(--radius-sm)",
        }}
      >
        {auth.statement_text}
      </blockquote>
      {(auth.client_ip || auth.user_agent) && (
        <p className="hint" style={{ marginBottom: 0 }}>
          {auth.client_ip && <>From {auth.client_ip}. </>}
          {auth.user_agent && <>Browser: {auth.user_agent}</>}
        </p>
      )}
    </div>
  );
}
