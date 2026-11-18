"use client";

import Link from "next/link";
import { use, useEffect, useMemo, useState } from "react";
import { OrgGate } from "../../../OrgGate";
import { ApiError, api, saveBlob } from "@/lib/api";
import { scanStatus } from "@/lib/scan";
import { CoverageCard } from "@/components/CoverageCard";
import { FindingsList, SeverityBar } from "@/components/FindingsList";
import type { Finding, Persona, Scan, ScanEndpoint, Target } from "@/lib/types";
import type { ScanAsset, ToolRun } from "@/lib/types";
import { hostStatus, techSummary } from "@/components/ReconPanel";

// Step 1C: the scan's report on one printable page (Print / Save as PDF) and
// as a JSON file. Built from the same data the scan page shows, so it can't
// disagree with it. The designed client report (severity scoring, merged
// duplicates, branded PDF) is a later step.

export default function ReportPage({ params }: { params: Promise<{ scanId: string }> }) {
  const { scanId } = use(params);
  return (
    <OrgGate>
      <Report scanId={scanId} />
    </OrgGate>
  );
}

interface Data {
  scan: Scan;
  target: Target;
  findings: Finding[];
  endpoints: ScanEndpoint[];
  personas: Persona[];
  assets: ScanAsset[];
  toolRuns: ToolRun[];
}

function Report({ scanId }: { scanId: string }) {
  const [data, setData] = useState<Data | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const scan = await api.getScan(scanId);
        const [target, findings, endpoints, personas, assets, toolRuns] = await Promise.all([
          api.getTarget(scan.target_id),
          api.listFindings(scanId),
          api.listScanEndpoints(scanId),
          api.listPersonas(scan.target_id),
          api.listScanAssets(scanId),
          api.listToolRuns(scanId),
        ]);
        if (!cancelled)
          setData({ scan, target, findings, endpoints, personas, assets, toolRuns });
      } catch (e) {
        if (!cancelled) setError(e instanceof ApiError ? e.detail : String(e));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [scanId]);

  const label = useMemo(() => {
    const names = new Map((data?.personas ?? []).map((p) => [p.id, p.label]));
    return (id: string) =>
      id === "anonymous" ? "Logged-out visitor" : (names.get(id) ?? "(deleted persona)");
  }, [data]);

  if (error)
    return (
      <div className="card">
        <h2>Report not available</h2>
        <p className="card-muted">{error}</p>
        <Link href={`/scans/${scanId}`}>← Back to the scan</Link>
      </div>
    );
  if (!data) return <div className="notice">Loading report…</div>;

  const { scan, target, findings, endpoints, assets, toolRuns } = data;
  const technologies = techSummary(assets);
  const status = scanStatus(scan);
  const confirmed = findings.filter((f) => f.confidence === "confirmed").length;

  function download() {
    const doc = {
      generated_at: new Date().toISOString(),
      target: { display_name: target.display_name, root_domain: target.root_domain },
      scan: {
        id: scan.id,
        status: status.label,
        state: scan.state,
        created_at: scan.created_at,
        finished_at: scan.finished_at,
        options: scan.options,
        is_degraded: scan.is_degraded,
        degraded_reasons: scan.degraded_reasons,
        phases: scan.phases.map((p) => ({ name: p.name, status: p.status, error: p.error })),
      },
      summary: {
        findings: findings.length,
        confirmed,
        probable: findings.length - confirmed,
        endpoints: endpoints.length,
      },
      findings,
      endpoints: endpoints.map((e) => ({ ...e, reached_by: e.persona_ids.map(label) })),
      hosts: assets.map((a) => ({
        host: a.host,
        status: hostStatus(a).label,
        reason: a.scope_reason,
        found_by: a.sources,
        ip_addresses: a.ip_addresses,
        http: a.http_probes.map((p) => ({ url: p.url, status_code: p.status_code, title: p.title })),
        technology: a.tech,
      })),
      technologies,
      tool_runs: toolRuns.map((r) => ({
        tool: r.tool,
        version: r.version,
        status: r.status,
        command: r.command,
        skip_reason: r.skip_reason,
        started_at: r.started_at,
        duration_ms: r.duration_ms,
        exit_code: r.exit_code,
        results: r.results_count,
      })),
    };
    saveBlob(
      new Blob([JSON.stringify(doc, null, 2)], { type: "application/json" }),
      `scan-${scan.id.slice(0, 8)}-report.json`,
    );
  }

  return (
    <>
      <div className="crumbs">
        <Link href="/">Targets</Link> / <Link href={`/targets/${scan.target_id}`}>{target.display_name}</Link>{" "}
        / <Link href={`/scans/${scan.id}`}>scan {scan.id.slice(0, 8)}</Link> / report
      </div>

      <div style={{ display: "flex", alignItems: "flex-start", gap: 12, marginTop: 8 }}>
        <div style={{ flex: 1 }}>
          <h1 style={{ marginBottom: 2 }}>Security scan report</h1>
          <div className="card-muted">
            {target.display_name} · <span className="mono">{target.root_domain}</span>
          </div>
          <div className="hint" style={{ marginTop: 4 }}>
            Scan {scan.id.slice(0, 8)} · {new Date(scan.finished_at ?? scan.created_at).toLocaleString()} ·{" "}
            <span className={`badge tone-${status.tone}`}>{status.label}</span>
          </div>
        </div>
        <button className="btn-sm no-print" onClick={download}>
          Download JSON
        </button>
        <button className="btn-sm btn-primary no-print" onClick={() => window.print()}>
          Print / Save as PDF
        </button>
      </div>

      <div className="card" style={{ marginTop: 16 }}>
        <h2>Summary</h2>
        <SeverityBar findings={findings} />
        <p style={{ margin: "10px 0 0" }}>
          {findings.length === 0
            ? "No findings were reported. "
            : `${findings.length} finding${findings.length === 1 ? "" : "s"} (${confirmed} confirmed by re-checking, ${findings.length - confirmed} probable). `}
          <b>
            {status.label === "Complete"
              ? "All planned checks ran."
              : "Not every check ran: see “What this scan covered” below. Zero findings only means the checks that ran found nothing."}
          </b>
        </p>
      </div>

      <CoverageCard scan={scan} />

      <div className="card" style={{ marginTop: 16 }}>
        <h2>Findings</h2>
        <FindingsList findings={findings} expanded />
      </div>

      <div className="card" style={{ marginTop: 16 }}>
        <h2>Pages and endpoints found ({endpoints.length})</h2>
        {endpoints.length === 0 ? (
          <div className="hint">None.</div>
        ) : (
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
            <thead>
              <tr style={{ textAlign: "left", color: "var(--text-dim)" }}>
                <th style={{ padding: "3px 8px" }}>Method</th>
                <th style={{ padding: "3px 8px" }}>Path</th>
                <th style={{ padding: "3px 8px" }}>Reached by</th>
              </tr>
            </thead>
            <tbody>
              {endpoints.map((e, i) => (
                <tr key={i} style={{ borderTop: "1px solid var(--border)" }}>
                  <td className="mono" style={{ padding: "3px 8px" }}>{e.method}</td>
                  <td className="mono" style={{ padding: "3px 8px", wordBreak: "break-all" }}>
                    {e.host}
                    {e.path_template}
                  </td>
                  <td style={{ padding: "3px 8px" }}>{e.persona_ids.map(label).join(", ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {assets.length > 0 && (
        <div className="card" style={{ marginTop: 16 }}>
          <h2>Hosts ({assets.length})</h2>
          <table className="report-table">
            <thead>
              <tr>
                <th>Host</th>
                <th>Status</th>
                <th>HTTP</th>
                <th>Found by</th>
                <th>Technology</th>
              </tr>
            </thead>
            <tbody>
              {assets.map((a) => (
                <tr key={a.host}>
                  <td className="mono">
                    {a.host}
                    {a.ip_addresses.length > 0 && <div className="hint">{a.ip_addresses.join(", ")}</div>}
                  </td>
                  <td>
                    {hostStatus(a).label}
                    {a.scope_reason && <div className="hint">{a.scope_reason}</div>}
                  </td>
                  <td>
                    {a.http_probes
                      .filter((p) => p.status_code !== null)
                      .slice(0, 2)
                      .map((p, i) => (
                        <div key={i}>
                          {p.status_code} {p.title ? `“${p.title}”` : ""}
                        </div>
                      ))}
                  </td>
                  <td>{(a.sources.length ? a.sources : [a.discovery_source]).join(", ")}</td>
                  <td>{a.tech.join(", ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {technologies.length > 0 && (
        <div className="card" style={{ marginTop: 16 }}>
          <h2>Technologies</h2>
          <table className="report-table">
            <thead>
              <tr>
                <th>Technology</th>
                <th>Version(s)</th>
                <th>Seen on</th>
              </tr>
            </thead>
            <tbody>
              {technologies.map((t) => (
                <tr key={t.name}>
                  <td>{t.name}</td>
                  <td className="mono">{t.versions.join(", ") || "—"}</td>
                  <td className="mono">{t.hosts.join(", ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="hint">Versions are read from responses: leads to confirm, not proof.</p>
        </div>
      )}

      {scan.degraded_reasons.length > 0 && (
        <div className="card" style={{ marginTop: 16 }}>
          <h2>Notes and limitations</h2>
          <ul style={{ margin: 0, paddingLeft: 18 }}>
            {scan.degraded_reasons.map((r, i) => (
              <li key={i}>{r}</li>
            ))}
          </ul>
        </div>
      )}

      {toolRuns.length > 0 && (
        <div className="card" style={{ marginTop: 16 }}>
          <h2>Appendix: commands run</h2>
          <table className="report-table">
            <thead>
              <tr>
                <th>Tool</th>
                <th>Result</th>
                <th>Command</th>
              </tr>
            </thead>
            <tbody>
              {toolRuns.map((r) => (
                <tr key={r.id}>
                  <td>
                    {r.tool} {r.version && <span className="mono">{r.version}</span>}
                  </td>
                  <td>
                    {r.status.replace("_", " ")}
                    <div className="hint">
                      {r.skip_reason ??
                        `${r.results_count} result(s)${r.duration_ms !== null ? `, ${(r.duration_ms / 1000).toFixed(1)} s` : ""}`}
                    </div>
                  </td>
                  <td className="mono" style={{ wordBreak: "break-all" }}>{r.command || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="hint">Full tool output is on the scan page (Tool runs → Download).</p>
        </div>
      )}
    </>
  );
}
