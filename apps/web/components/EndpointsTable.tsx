"use client";

import { useEffect, useMemo, useState } from "react";
import { ApiError, api } from "@/lib/api";
import type { Persona, ScanEndpoint } from "@/lib/types";

// Step 1B: every page and API call the crawl found, and which identity
// reached it. The quickest way to check a scan: open the real site, compare.
// A page reached only by a logged-in identity (and not the logged-out visitor)
// is exactly the surface the authorization check protects.

const SOURCE_TEXT: Record<string, string> = {
  rendered_crawl: "link or form",
  js_extraction: "background request",
};

export function EndpointsTable({ scanId, targetId }: { scanId: string; targetId: string }) {
  const [rows, setRows] = useState<ScanEndpoint[] | null>(null);
  const [personas, setPersonas] = useState<Persona[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loggedInOnly, setLoggedInOnly] = useState(false);
  const [query, setQuery] = useState("");

  useEffect(() => {
    let cancelled = false;
    api
      .listScanEndpoints(scanId)
      .then((r) => !cancelled && setRows(r))
      .catch((e) => !cancelled && setError(e instanceof ApiError ? e.detail : String(e)));
    api
      .listPersonas(targetId)
      .then((p) => !cancelled && setPersonas(p))
      .catch(() => undefined); // names fall back to "deleted persona"
    return () => {
      cancelled = true;
    };
  }, [scanId, targetId]);

  const name = (id: string) =>
    id === "anonymous"
      ? "Logged-out visitor"
      : (personas.find((p) => p.id === id)?.label ?? "(deleted persona)");

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (rows ?? []).filter(
      (r) =>
        (!loggedInOnly || !r.persona_ids.includes("anonymous")) &&
        (!q || `${r.host}${r.path_template}`.toLowerCase().includes(q)),
    );
  }, [rows, loggedInOnly, query]);

  const onlyLoggedIn = (rows ?? []).filter((r) => !r.persona_ids.includes("anonymous")).length;

  return (
    <div className="card" style={{ marginTop: 16 }}>
      <h2>Pages and endpoints found</h2>
      {error && <div className="error-box">{error}</div>}
      {!rows && !error && <div className="hint">Loading…</div>}
      {rows && rows.length === 0 && (
        <div className="empty">
          The crawl found nothing. Check the target domain (the app may live on a{" "}
          <span className="mono">www.</span> host) and the activity log above for why.
        </div>
      )}
      {rows && rows.length > 0 && (
        <>
          <p className="card-muted" style={{ marginTop: 0 }}>
            {rows.length} found; {onlyLoggedIn} reached only when logged in. Compare this list with
            the real site to see what the crawl covered.
          </p>
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap", margin: "6px 0 10px" }}>
            <input
              placeholder="Filter by path…"
              value={query}
              aria-label="Filter by path"
              onChange={(e) => setQuery(e.target.value)}
              style={{ maxWidth: 260 }}
            />
            <label style={{ display: "flex", gap: 6, alignItems: "center" }}>
              <input
                type="checkbox"
                checked={loggedInOnly}
                onChange={(e) => setLoggedInOnly(e.target.checked)}
                style={{ width: "auto" }}
              />
              Only reached when logged in
            </label>
          </div>
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
              <thead>
                <tr style={{ textAlign: "left", color: "var(--text-dim)" }}>
                  <th style={{ padding: "4px 8px" }}>Method</th>
                  <th style={{ padding: "4px 8px" }}>Path</th>
                  <th style={{ padding: "4px 8px" }}>Reached by</th>
                  <th style={{ padding: "4px 8px" }}>Found via</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((r, i) => (
                  <tr key={`${r.host}-${r.method}-${r.path_template}-${i}`} style={{ borderTop: "1px solid var(--border)" }}>
                    <td style={{ padding: "4px 8px" }} className="mono">{r.method}</td>
                    <td style={{ padding: "4px 8px", wordBreak: "break-all" }} className="mono">
                      <span style={{ color: "var(--text-dim)" }}>{r.host}</span>
                      {r.path_template}
                    </td>
                    <td style={{ padding: "4px 8px" }}>
                      {r.persona_ids.map((id) => (
                        <span key={id} className="badge tone-muted" style={{ marginRight: 4 }}>
                          ✓ {name(id)}
                        </span>
                      ))}
                    </td>
                    <td style={{ padding: "4px 8px", color: "var(--text-dim)" }}>
                      {SOURCE_TEXT[r.source] ?? r.source}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {filtered.length === 0 && <div className="hint">Nothing matches these filters.</div>}
        </>
      )}
    </div>
  );
}
