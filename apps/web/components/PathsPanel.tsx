"use client";

import { useId, useMemo, useState } from "react";
import { api, saveBlob } from "@/lib/api";
import {
  PATH_RENDER_LIMIT,
  categoryLabel,
  filterPaths,
  findingAnchor,
  formatSize,
  isHttpUrl,
  pathsToCsv,
  statusTone,
} from "@/lib/paths";
import type { DiscoveredPath } from "@/lib/types";
import { usePoll } from "@/lib/usePoll";

// Paths found by directory/file brute force: which host, which path, what
// the server answered, and whether we proved it (re-checked through the
// guarded HTTP engine and linked to a finding). Shown only when rows exist or
// the scan asked for the tool, so ordinary scans see no extra card.

// Rule ids and verdicts are read as written (the badge default is UPPERCASE).
const NO_CAPS = { textTransform: "none" } as const;

export function VerdictCell({ row }: { row: DiscoveredPath }) {
  if (row.verdict === "confirmed") {
    const label = row.rule_id ? `Confirmed: ${row.rule_id}` : "Confirmed";
    return row.finding_id ? (
      <a href={findingAnchor(row.finding_id)} title="Go to the finding">
        <span className="badge tone-bad" style={NO_CAPS}>{label}</span>
      </a>
    ) : (
      <span className="badge tone-bad" style={NO_CAPS}>{label}</span>
    );
  }
  if (row.verdict === "not_confirmed") {
    return (
      <>
        <span className="badge tone-muted" style={NO_CAPS}>Not confirmed</span>
        {/* The note is plain text: React escapes it, it is never HTML. */}
        {row.note && <div className="hint">{row.note}</div>}
      </>
    );
  }
  return (
    <>
      <span className="badge tone-muted" style={NO_CAPS}>
        {row.verdict === "found" ? "Found" : row.verdict}
      </span>
      {row.note && <div className="hint">{row.note}</div>}
    </>
  );
}

export function PathsPanel({
  scanId,
  running,
  enabled,
}: {
  scanId: string;
  running: boolean;
  // The scan asked for directory brute force (scan.options.dir_bruteforce).
  enabled: boolean;
}) {
  const paths = usePoll(() => api.listScanPaths(scanId), 10000, running);
  const uid = useId();
  const [category, setCategory] = useState("");
  const [confirmedOnly, setConfirmedOnly] = useState(false);
  const [text, setText] = useState("");
  const [downloadError, setDownloadError] = useState<string | null>(null);

  const all = useMemo(() => paths.data ?? [], [paths.data]);
  const categories = useMemo(() => [...new Set(all.map((r) => r.category))].sort(), [all]);
  const filtered = useMemo(
    () => filterPaths(all, { category, confirmedOnly, text }),
    [all, category, confirmedOnly, text],
  );
  const shown = filtered.slice(0, PATH_RENDER_LIMIT);
  const confirmedCount = useMemo(() => all.filter((r) => r.verdict === "confirmed").length, [all]);

  // Nothing to show for a scan that did not use the tool (also covers the
  // endpoint being absent or failing on an old API).
  if (all.length === 0 && !enabled) return null;

  const title = "Paths found by directory brute force";

  if (all.length === 0) {
    return (
      <div className="card" style={{ marginTop: 16 }} id="paths">
        <h2>{title}</h2>
        {paths.error ? (
          <div className="error-box">Could not load the paths: {paths.error}</div>
        ) : !paths.data ? (
          <div className="hint">Loading…</div>
        ) : (
          <div className="empty">
            {running
              ? "Results appear here once the directory brute force step has run."
              : "No paths are recorded for this scan. The brute force may have found nothing beyond what the crawl saw, or it may not have run: the Activity log and the Tool runs above say which."}
          </div>
        )}
      </div>
    );
  }

  function download() {
    setDownloadError(null);
    try {
      saveBlob(
        new Blob([pathsToCsv(filtered)], { type: "text/csv;charset=utf-8" }),
        `scan-${scanId.slice(0, 8)}-paths.csv`,
      );
    } catch (e) {
      setDownloadError(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <div className="card" style={{ marginTop: 16 }} id="paths">
      <h2>{title}</h2>
      {paths.error && <div className="error-box">Could not refresh the paths: {paths.error}</div>}
      <p className="card-muted" style={{ marginTop: 0 }}>
        {all.length} path(s) found, {confirmedCount} confirmed by re-checking. A path that is only
        “Found” answered the request but is not proof of a problem.
      </p>

      <div className="row" style={{ marginBottom: 10 }}>
        <div>
          <label htmlFor={`${uid}-cat`}>Category</label>
          <select id={`${uid}-cat`} value={category} onChange={(e) => setCategory(e.target.value)}>
            <option value="">All categories</option>
            {categories.map((c) => (
              <option key={c} value={c}>
                {categoryLabel(c)}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label htmlFor={`${uid}-verdict`}>Verdict</label>
          <select
            id={`${uid}-verdict`}
            value={confirmedOnly ? "confirmed" : "all"}
            onChange={(e) => setConfirmedOnly(e.target.value === "confirmed")}
          >
            <option value="all">All</option>
            <option value="confirmed">Confirmed only</option>
          </select>
        </div>
        <div style={{ flex: 2 }}>
          <label htmlFor={`${uid}-text`}>Filter by path</label>
          <input
            id={`${uid}-text`}
            type="text"
            value={text}
            placeholder="e.g. .env or admin"
            onChange={(e) => setText(e.target.value)}
          />
        </div>
        <div style={{ flex: "0 0 auto", minWidth: 0 }}>
          <button type="button" className="btn-sm" onClick={download} disabled={filtered.length === 0}>
            Download CSV
          </button>
        </div>
      </div>
      {downloadError && <div className="error-box">{downloadError}</div>}

      <div className="hint" role="status" aria-live="polite" style={{ marginBottom: 6 }}>
        showing {shown.length.toLocaleString()} of {all.length.toLocaleString()}
        {filtered.length !== all.length && <> ({filtered.length.toLocaleString()} match the filters)</>}
      </div>
      {filtered.length > PATH_RENDER_LIMIT && (
        <div className="notice" style={{ marginBottom: 8 }}>
          Showing the first {PATH_RENDER_LIMIT} of {filtered.length.toLocaleString()} matching rows.
          Download the CSV for all of them.
        </div>
      )}

      {filtered.length === 0 ? (
        <div className="empty">No paths match these filters.</div>
      ) : (
        <div style={{ overflowX: "auto" }}>
          <table className="report-table" aria-label={title}>
            <thead>
              <tr>
                <th scope="col">Host</th>
                <th scope="col">Path</th>
                <th scope="col">Status</th>
                <th scope="col">Size</th>
                <th scope="col">Type</th>
                <th scope="col">Category</th>
                <th scope="col">Verdict</th>
                <th scope="col">Used for crawl</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((r) => (
                <tr key={r.id}>
                  <td className="mono" style={{ overflowWrap: "anywhere", minWidth: 190 }}>{r.origin}</td>
                  <td className="mono" style={{ overflowWrap: "anywhere", minWidth: 150 }}>
                    {isHttpUrl(r.url) ? (
                      <a href={r.url} target="_blank" rel="noopener noreferrer">
                        {r.path}
                      </a>
                    ) : (
                      r.path
                    )}
                    {r.redirect_location && (
                      <div className="hint" style={{ wordBreak: "break-all" }}>
                        redirects to {r.redirect_location}
                      </div>
                    )}
                  </td>
                  <td>
                    <span className={`badge ${statusTone(r.status_code)}`} style={{ whiteSpace: "nowrap" }}>{r.status_code}</span>
                  </td>
                  <td style={{ whiteSpace: "nowrap" }}>{formatSize(r.content_length)}</td>
                  <td className="mono" style={{ overflowWrap: "anywhere" }}>{r.content_type ?? "—"}</td>
                  <td>
                    <span className="badge tone-muted" style={{ whiteSpace: "nowrap" }}>{categoryLabel(r.category)}</span>
                  </td>
                  <td>
                    <VerdictCell row={r} />
                  </td>
                  <td>
                    {r.crawl_seed ? (
                      <span className="badge tone-running" title="This path was given to the crawler as a starting page">
                        Yes
                      </span>
                    ) : (
                      <span className="hint">No</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
