"use client";

import Link from "next/link";
import { use } from "react";
import { OrgGate } from "../../OrgGate";
import { api } from "@/lib/api";
import { usePoll } from "@/lib/usePoll";
import { STATE_LABEL, isFailureState, isTerminal } from "@/lib/scan";
import { PhaseBoard } from "@/components/PhaseBoard";
import { FindingsList, SeverityBar } from "@/components/FindingsList";
import type { Finding, Scan } from "@/lib/types";

export default function ScanPage({ params }: { params: Promise<{ scanId: string }> }) {
  const { scanId } = use(params);
  return (
    <OrgGate>
      <ScanDetail scanId={scanId} />
    </OrgGate>
  );
}

function ScanDetail({ scanId }: { scanId: string }) {
  const { data: scan, error } = usePoll<Scan>(() => api.getScan(scanId), 3000, true);
  const terminal = scan ? isTerminal(scan.state) : false;

  // Findings poll alongside the scan, but stop once the scan is terminal.
  const { data: findings } = usePoll<Finding[]>(
    () => api.listFindings(scanId),
    5000,
    !terminal,
  );

  return (
    <>
      <div className="crumbs">
        <Link href="/">Targets</Link> /{" "}
        {scan ? <Link href={`/targets/${scan.target_id}`}>target</Link> : "…"} / scan{" "}
        {scanId.slice(0, 8)}
      </div>

      {error && <div className="error-box">{error}</div>}
      {!scan ? (
        <div className="notice">Loading scan…</div>
      ) : (
        <>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginTop: 8 }}>
            <h1 style={{ margin: 0 }}>Scan</h1>
            <StatePill scan={scan} />
            {!terminal && <span className="hint">live · refreshing every 3s</span>}
          </div>

          {scan.fail_reason && (
            <div className="error-box" style={{ marginTop: 12 }}>
              {scan.fail_reason}
            </div>
          )}

          {scan.is_degraded && scan.degraded_reasons.length > 0 && (
            <div className="notice" style={{ marginTop: 12 }}>
              <strong>Running in degraded mode:</strong>
              <ul style={{ margin: "6px 0 0" }}>
                {scan.degraded_reasons.map((r, i) => (
                  <li key={i}>{r}</li>
                ))}
              </ul>
            </div>
          )}

          <div className="grid grid-2" style={{ marginTop: 16 }}>
            <div className="card" style={{ margin: 0 }}>
              <h2>Progress</h2>
              <PhaseBoard scan={scan} />
            </div>

            <div className="card" style={{ margin: 0 }}>
              <h2>Findings</h2>
              <SeverityBar findings={findings ?? []} />
              <div style={{ marginTop: 14 }}>
                <FindingsList findings={findings ?? []} />
              </div>

              <h3 style={{ marginTop: 20 }}>LLM budget</h3>
              <div className="hint">
                {scan.llm_tokens_used.toLocaleString()} /{" "}
                {scan.llm_token_budget.toLocaleString()} tokens
              </div>
              <div className="meter">
                <span
                  style={{
                    width: `${Math.min(
                      100,
                      scan.llm_token_budget
                        ? (scan.llm_tokens_used / scan.llm_token_budget) * 100
                        : 0,
                    )}%`,
                  }}
                />
              </div>
            </div>
          </div>
        </>
      )}
    </>
  );
}

function StatePill({ scan }: { scan: Scan }) {
  const tone = isFailureState(scan.state)
    ? "bad"
    : scan.state === "complete"
      ? "ok"
      : isTerminal(scan.state)
        ? "muted"
        : "running";
  return <span className={`badge tone-${tone}`}>{STATE_LABEL[scan.state]}</span>;
}
