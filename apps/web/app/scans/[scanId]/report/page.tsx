"use client";

import Link from "next/link";
import { use, useEffect, useMemo, useState } from "react";
import { OrgGate } from "../../../OrgGate";
import { ApiError, api, saveBlob } from "@/lib/api";
import { scanStatus } from "@/lib/scan";
import { CoverageCard } from "@/components/CoverageCard";
import { FindingsList, SeverityBar } from "@/components/FindingsList";
import type { Finding, Persona, Scan, ScanEndpoint, Target } from "@/lib/types";

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
  assets: { host: string; ip_addresses: string[]; tech_fingerprint: string[] }[];
}

function Report({ scanId }: { scanId: string }) {
  const [data, setData] = useState<Data | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const scan = await api.getScan(scanId);
        const [target, findings, endpoints, personas, stored] = await Promise.all([
          api.getTarget(scan.target_id),
          api.listFindings(scanId),
          api.listScanEndpoints(scanId),
          api.listPersonas(scan.target_id),
          api.getScanReport(scanId).catch(() => null), // only the host list comes from it
        ]);
        const assets = Array.isArray(stored?.assets)
          ? (stored.assets as Data["assets"])
          : [];
        if (!cancelled) setData({ scan, target, findings, endpoints, personas, assets });
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

  const { scan, target, findings, endpoints, assets } = data;
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
      hosts: assets,
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
          <h2>Hosts</h2>
          <ul style={{ margin: 0, paddingLeft: 18 }}>
            {assets.map((a) => (
              <li key={a.host}>
                <span className="mono">{a.host}</span>
                {a.ip_addresses.length > 0 && ` — ${a.ip_addresses.join(", ")}`}
                {a.tech_fingerprint.length > 0 && ` — ${a.tech_fingerprint.join(", ")}`}
              </li>
            ))}
          </ul>
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
    </>
  );
}
