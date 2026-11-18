"use client";

import { useMemo, useState } from "react";
import { ApiError, api, downloadToolOutput } from "@/lib/api";
import type { ScanAsset, ToolRun } from "@/lib/types";
import { usePoll } from "@/lib/usePoll";

// Recon, the way a tester checks it: which hosts were found and by which
// data source, which were probed (and if not, why), what technology each
// one runs, and the exact command, version and raw output of every tool.

const SCOPE_TEXT: Record<string, { label: string; tone: string }> = {
  excluded: { label: "out of scope", tone: "tone-muted" },
  private_ip: { label: "private address", tone: "tone-bad" },
  unresolved: { label: "no DNS", tone: "tone-muted" },
  capped: { label: "over host limit", tone: "tone-muted" },
};

const RUN_TONE: Record<string, string> = {
  ok: "tone-ok",
  skipped: "tone-muted",
  not_installed: "tone-bad",
  failed: "tone-bad",
  timed_out: "tone-bad",
};

const cell = { padding: "4px 8px", verticalAlign: "top" } as const;

export function hostStatus(a: ScanAsset): { label: string; tone: string } {
  if (a.scope_status !== "in_scope") return SCOPE_TEXT[a.scope_status] ?? { label: a.scope_status, tone: "tone-muted" };
  return a.live ? { label: "live", tone: "tone-ok" } : { label: "not answering", tone: "tone-muted" };
}

/** "PHP:7.4.3" -> ["PHP", "7.4.3"]; "nginx" -> ["nginx", ""]. */
function splitTech(t: string): [string, string] {
  const i = t.lastIndexOf(":");
  return i > 0 ? [t.slice(0, i), t.slice(i + 1)] : [t, ""];
}

export function techSummary(assets: ScanAsset[]): { name: string; versions: string[]; hosts: string[] }[] {
  const byName = new Map<string, { versions: Set<string>; hosts: Set<string> }>();
  for (const a of assets) {
    for (const t of a.tech) {
      const [name, version] = splitTech(t);
      const entry = byName.get(name) ?? { versions: new Set(), hosts: new Set() };
      if (version) entry.versions.add(version);
      entry.hosts.add(a.host);
      byName.set(name, entry);
    }
  }
  return [...byName.entries()]
    .map(([name, e]) => ({ name, versions: [...e.versions].sort(), hosts: [...e.hosts].sort() }))
    .sort((x, y) => y.hosts.length - x.hosts.length || x.name.localeCompare(y.name));
}

function duration(ms: number | null): string {
  if (ms === null) return "";
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`;
}

export function ReconPanel({ scanId, running }: { scanId: string; running: boolean }) {
  const assets = usePoll(() => api.listScanAssets(scanId), 10000, running);
  const runs = usePoll(() => api.listToolRuns(scanId), 10000, running);
  const [showSkipped, setShowSkipped] = useState(false);
  const [downloadError, setDownloadError] = useState<string | null>(null);

  const all = assets.data ?? [];
  const tech = useMemo(() => techSummary(all), [all]);
  const probed = all.filter((a) => a.scope_status === "in_scope");
  const notProbed = all.length - probed.length;
  const shown = showSkipped ? all : probed;

  if (!assets.data && !runs.data && !assets.error) {
    return (
      <div className="card" style={{ marginTop: 16 }}>
        <h2>Recon</h2>
        <div className="hint">Loading…</div>
      </div>
    );
  }
  if (all.length === 0 && (runs.data ?? []).length === 0) {
    return (
      <div className="card" style={{ marginTop: 16 }}>
        <h2>Recon</h2>
        <div className="empty">
          {running ? "Recon results appear here once the recon phase finishes." : "This scan has no recon results (it ran before tool records were kept, or stopped before recon)."}
        </div>
      </div>
    );
  }

  const download = (run: ToolRun, stream: "stdout" | "stderr") => {
    setDownloadError(null);
    downloadToolOutput(scanId, run, stream).catch((e) =>
      setDownloadError(e instanceof ApiError ? e.detail : String(e)),
    );
  };

  return (
    <div className="card" style={{ marginTop: 16 }}>
      <h2>Recon: hosts, technologies and tool runs</h2>
      {(assets.error || runs.error) && <div className="error-box">{assets.error || runs.error}</div>}
      <p className="card-muted" style={{ marginTop: 0 }}>
        {all.length} host(s) found, {all.filter((a) => a.live).length} answering over HTTP
        {notProbed > 0 && <>, {notProbed} not probed (see why with “Show hosts not probed”)</>}.
      </p>

      <h3>Hosts</h3>
      {notProbed > 0 && (
        <label style={{ display: "flex", gap: 6, alignItems: "center", margin: "4px 0 8px" }}>
          <input
            type="checkbox"
            checked={showSkipped}
            onChange={(e) => setShowSkipped(e.target.checked)}
            style={{ width: "auto" }}
          />
          Show hosts not probed ({notProbed})
        </label>
      )}
      <div style={{ overflowX: "auto" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
          <thead>
            <tr style={{ textAlign: "left", color: "var(--text-dim)" }}>
              <th style={cell}>Host</th>
              <th style={cell}>Status</th>
              <th style={cell}>HTTP</th>
              <th style={cell}>IPs</th>
              <th style={cell}>Found by</th>
              <th style={cell}>Technology</th>
            </tr>
          </thead>
          <tbody>
            {shown.map((a) => {
              const st = hostStatus(a);
              return (
                <tr key={a.host} style={{ borderTop: "1px solid var(--border)" }}>
                  <td style={{ ...cell, wordBreak: "break-all" }} className="mono">
                    {a.host}
                    {a.endpoints > 0 && <div className="hint">{a.endpoints} endpoint(s) crawled</div>}
                  </td>
                  <td style={cell}>
                    <span className={`badge ${st.tone}`}>{st.label}</span>
                    {a.scope_reason && <div className="hint">{a.scope_reason}</div>}
                  </td>
                  <td style={{ ...cell, wordBreak: "break-all" }}>
                    {a.http_probes.slice(0, 2).map((p, i) => (
                      <div key={i}>
                        <span className="mono">{p.status_code ?? "—"}</span>{" "}
                        <span style={{ color: "var(--text-dim)" }}>{p.url}</span>
                        {p.title && <div>“{p.title}”</div>}
                        {p.cdn && <div className="hint">behind {p.cdn}</div>}
                        {p.error && <div className="hint">{p.error}</div>}
                      </div>
                    ))}
                  </td>
                  <td style={cell} className="mono">
                    {a.ip_addresses.join(", ") || "—"}
                  </td>
                  <td style={cell}>{(a.sources.length ? a.sources : [a.discovery_source]).join(", ")}</td>
                  <td style={cell}>
                    {a.tech.map((t) => (
                      <span key={t} className="badge tone-muted" style={{ marginRight: 4, marginBottom: 2, textTransform: "none" }}>
                        {t}
                      </span>
                    ))}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <h3 style={{ marginTop: 20 }}>Technologies</h3>
      {tech.length === 0 ? (
        <div className="hint">No technology identified (needs a live host; httpx adds Wappalyzer-based detection).</div>
      ) : (
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
          <thead>
            <tr style={{ textAlign: "left", color: "var(--text-dim)" }}>
              <th style={cell}>Technology</th>
              <th style={cell}>Version(s)</th>
              <th style={cell}>Seen on</th>
            </tr>
          </thead>
          <tbody>
            {tech.map((t) => (
              <tr key={t.name} style={{ borderTop: "1px solid var(--border)" }}>
                <td style={cell}>{t.name}</td>
                <td style={cell} className="mono">{t.versions.join(", ") || "—"}</td>
                <td style={{ ...cell, wordBreak: "break-all" }} className="mono">{t.hosts.join(", ")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <p className="hint">
        Versions come from response headers and page content, so treat them as leads to confirm,
        not proof.
      </p>

      <h3 style={{ marginTop: 20 }}>Tool runs</h3>
      {downloadError && <div className="error-box">{downloadError}</div>}
      {(runs.data ?? []).map((r) => (
        <details key={r.id} className="ev" style={{ marginBottom: 8 }}>
          <summary>
            <strong>{r.tool}</strong> {r.version && <span className="mono">{r.version}</span>}{" "}
            <span className={`badge ${RUN_TONE[r.status] ?? "tone-muted"}`}>{r.status.replace("_", " ")}</span>{" "}
            <span className="hint">
              {r.status === "skipped" || r.status === "not_installed"
                ? r.skip_reason
                : `${r.results_count} result(s)${r.duration_ms !== null ? `, ${duration(r.duration_ms)}` : ""}${r.exit_code !== null ? `, exit ${r.exit_code}` : ""}`}
            </span>
          </summary>
          {r.command && (
            <>
              <div className="hint" style={{ marginTop: 6 }}>Command</div>
              <pre className="block">{r.command}</pre>
            </>
          )}
          {r.started_at && (
            <div className="hint">
              Started {new Date(r.started_at).toLocaleString()}
              {r.timed_out && " — stopped at the time limit; output so far is kept"}
            </div>
          )}
          {(["stdout", "stderr"] as const).map((stream) => {
            const chars = stream === "stdout" ? r.stdout_chars : r.stderr_chars;
            const preview = stream === "stdout" ? r.stdout_preview : r.stderr_preview;
            if (!chars) return null;
            return (
              <div key={stream} style={{ marginTop: 8 }}>
                <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
                  <span className="hint">
                    {stream === "stdout" ? "Output (results)" : "Messages (stderr)"} —{" "}
                    {chars.toLocaleString()} characters
                    {chars > preview.length && ", first part shown"}
                    {(stream === "stdout" ? r.stdout_truncated : r.stderr_truncated) && ", cut at the stored limit"}
                  </span>
                  <button type="button" className="btn-sm" onClick={() => download(r, stream)}>
                    Download
                  </button>
                </div>
                <pre className="block" style={{ maxHeight: 280, overflow: "auto" }}>{preview}</pre>
              </div>
            );
          })}
        </details>
      ))}
    </div>
  );
}
