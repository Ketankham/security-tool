"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { use, useState } from "react";
import { OrgGate } from "../../OrgGate";
import { ApiError, api } from "@/lib/api";
import { usePoll } from "@/lib/usePoll";
import { isTerminal, scanStatus } from "@/lib/scan";
import { activeToolsOf } from "@/lib/activeTools";
import { ActivityLog } from "@/components/ActivityLog";
import { AuthorisationCard } from "@/components/AuthorisationCard";
import { CoverageCard } from "@/components/CoverageCard";
import { RetryModal } from "@/components/RetryModal";
import { EndpointsTable } from "@/components/EndpointsTable";
import { ReconPanel } from "@/components/ReconPanel";
import { PathsPanel } from "@/components/PathsPanel";
import { PortsPanel } from "@/components/PortsPanel";
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
  const { data: scan, error, refresh } = usePoll<Scan>(() => api.getScan(scanId), 3000, true);
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

      {error && scan && <div className="error-box">{error}</div>}
      {error && !scan ? (
        <div className="card">
          <h2>Scan not found</h2>
          <p className="card-muted">
            This scan doesn&apos;t exist, or it belongs to a different organization. ({error})
          </p>
          <Link href="/">← Back to targets</Link>
        </div>
      ) : !scan ? (
        <div className="notice">Loading scan…</div>
      ) : (
        <>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginTop: 8 }}>
            <h1 style={{ margin: 0 }}>Scan</h1>
            <StatePill scan={scan} />
            {!terminal && <span className="hint">live · refreshing every 3s</span>}
            <span style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 8 }}>
              {scan.state === "complete" && (
                <Link href={`/scans/${scan.id}/report`} className="btn-sm">
                  View report
                </Link>
              )}
              {!terminal && <CancelButton scan={scan} onChanged={refresh} />}
              {terminal && <RetryButton scan={scan} />}
            </span>
          </div>
          <div className="hint" style={{ marginTop: 4 }}>
            Started by {scan.requested_by ? <strong>{scan.requested_by}</strong> : "unknown"}
            {" · "}
            {new Date(scan.started_at ?? scan.created_at).toLocaleString()}
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

          {terminal && scan.state === "complete" && <CoverageCard scan={scan} />}

          <div className="grid grid-2" style={{ marginTop: 16 }}>
            <div className="card" style={{ margin: 0 }}>
              <h2>Progress</h2>
              <PhaseBoard scan={scan} />
            </div>

            <div className="card" style={{ margin: 0 }} id="findings">
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

          <AuthorisationCard scanId={scan.id} />
          <ActivityLog scanId={scan.id} running={!terminal} />
          <ReconPanel scanId={scan.id} running={!terminal} />
          <PathsPanel
            scanId={scan.id}
            running={!terminal}
            enabled={scan.options?.dir_bruteforce === true}
          />
          <PortsPanel
            scanId={scan.id}
            running={!terminal}
            enabled={scan.options?.port_scan === true}
          />
          {(scan.state === "complete" || scan.state === "failed") && (
            <EndpointsTable scanId={scan.id} targetId={scan.target_id} />
          )}
        </>
      )}
    </>
  );
}

function StatePill({ scan }: { scan: Scan }) {
  const { label, tone } = scanStatus(scan);
  return <span className={`badge tone-${tone}`}>{label}</span>;
}

// Stops a running scan. Cancelling is cooperative: the API records the request
// and the worker stops at its next checkpoint (about a second inside a tool),
// so the scan stays "running" for a moment and then turns Cancelled.
function CancelButton({ scan, onChanged }: { scan: Scan; onChanged: () => void }) {
  const [busy, setBusy] = useState(false);
  const [requested, setRequested] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function cancel() {
    if (
      !window.confirm(
        "Cancel this scan? Tests in progress are stopped and the scan can't be resumed " +
          "(you can run it again afterwards).",
      )
    ) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await api.cancelScan(scan.id);
      setRequested(true);
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) {
        // Already finished (or finishing): just show its real state.
        setError("This scan has already finished, so there is nothing to cancel.");
      } else {
        setError(err instanceof ApiError ? err.detail : String(err));
      }
    } finally {
      setBusy(false);
      onChanged();
    }
  }

  return (
    <span style={{ display: "flex", alignItems: "center", gap: 8 }}>
      {error && <span className="field-error" style={{ display: "inline" }}>{error}</span>}
      {requested && !error && <span className="hint">Cancelling… stops at the next checkpoint.</span>}
      <button onClick={cancel} disabled={busy || requested}>
        {busy ? "Cancelling…" : requested ? "Cancel requested" : "Cancel scan"}
      </button>
    </span>
  );
}

// v1 #2: any finished scan can be run again. A failed one gets a prominent
// "Retry scan"; a completed one a quieter "Run again". Both start a fresh
// scan of the same target (the old one stays as history) and open it.
// A scan that used active tools answers 409: its retry must be re-authorised
// (or drop the tools), which the dialog handles.
function RetryButton({ scan }: { scan: Scan }) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [needsConfirm, setNeedsConfirm] = useState<string | null>(null);
  const failed = scan.state !== "complete";
  const tools = activeToolsOf(scan.options);

  async function retry() {
    setBusy(true);
    setError(null);
    try {
      const next = await api.retryScan(scan.id);
      router.push(`/scans/${next.id}`);
    } catch (err) {
      if (err instanceof ApiError && err.status === 409 && tools.length > 0) {
        setNeedsConfirm(err.detail);
      } else {
        setError(err instanceof ApiError ? err.detail : String(err));
      }
      setBusy(false);
    }
  }

  return (
    <span style={{ display: "flex", alignItems: "center", gap: 8 }}>
      {error && <span className="field-error" style={{ display: "inline" }}>{error}</span>}
      <button className={failed ? "btn-primary" : undefined} onClick={retry} disabled={busy}>
        {busy ? "Starting…" : failed ? "Retry scan" : "Run again"}
      </button>
      {needsConfirm !== null && (
        <RetryModal
          scan={scan}
          tools={tools}
          serverMessage={needsConfirm}
          onClose={() => setNeedsConfirm(null)}
          onStarted={(id) => router.push(`/scans/${id}`)}
        />
      )}
    </span>
  );
}
