"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { use, useEffect, useState } from "react";
import { OrgGate } from "../../OrgGate";
import { ApiError, api } from "@/lib/api";
import { usePoll } from "@/lib/usePoll";
import { CHECK_PHASES, PHASE_LABEL, crawlStats, isTerminal, scanStatus } from "@/lib/scan";
import { PhaseBoard } from "@/components/PhaseBoard";
import { FindingsList, SeverityBar } from "@/components/FindingsList";
import type { Finding, Persona, Scan } from "@/lib/types";

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
            {terminal && <RetryButton scan={scan} />}
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
  const { label, tone } = scanStatus(scan);
  return <span className={`badge tone-${tone}`}>{label}</span>;
}

const SPEED_TEXT: Record<string, string> = { gentle: "gentle (2 req/s)", normal: "normal (5 req/s)", fast: "fast (10 req/s)" };
const DEPTH_TEXT: Record<string, string> = { quick: "quick (30 pages)", standard: "standard (100 pages)", deep: "deep (300 pages)" };

// QA #38: say plainly what this scan did and did not look at, so "0 findings"
// on a scan that crawled one page and skipped most checks isn't read as clean.
function CoverageCard({ scan }: { scan: Scan }) {
  const [personas, setPersonas] = useState<Persona[] | null>(null);
  useEffect(() => {
    api.listPersonas(scan.target_id).then(setPersonas).catch(() => setPersonas([]));
  }, [scan.target_id]);
  const label = (id: string) =>
    id === "anonymous" ? "Logged-out visitor" : (personas?.find((p) => p.id === id)?.label ?? id.slice(0, 8));

  const { pagesByPersona, endpointsByPersona } = crawlStats(scan);
  const crawled = Object.keys(pagesByPersona).length > 0;
  const maxPages = Math.max(0, ...Object.values(pagesByPersona));
  const auth = scan.phases.find((p) => p.name === "auth_establishing")?.stats_json as
    | { personas_configured?: number; personas_available?: number }
    | undefined;
  const ran = scan.phases.filter((p) => CHECK_PHASES.includes(p.name) && p.status === "completed");
  const skipped = scan.phases.filter((p) => CHECK_PHASES.includes(p.name) && p.status === "skipped");

  return (
    <div className="card" style={{ marginTop: 16 }}>
      <h2>What this scan covered</h2>
      {crawled && maxPages <= 2 && (
        <div className="error-box" style={{ marginBottom: 10 }}>
          The crawl only reached {maxPages} page{maxPages === 1 ? "" : "s"}, so these results cover
          very little of the site. Check the target domain (e.g. the app may live on{" "}
          <span className="mono">www.</span>) and that the logins work (Test login), then run again.
        </div>
      )}
      <ul style={{ margin: 0, paddingLeft: 18, lineHeight: 1.7 }}>
        {(scan.options?.speed || scan.options?.depth) && (
          <li>
            Settings: speed {SPEED_TEXT[scan.options.speed ?? "normal"]}, depth{" "}
            {DEPTH_TEXT[scan.options.depth ?? "standard"]}
          </li>
        )}
        {auth && (auth.personas_configured ?? 0) > 0 && (
          <li>
            Logins: {auth.personas_available ?? 0} of {auth.personas_configured} worked
          </li>
        )}
        {crawled && (
          <li>
            Crawled:{" "}
            {Object.entries(pagesByPersona)
              .map(([id, n]) => `${label(id)}: ${n} page${n === 1 ? "" : "s"}, ${endpointsByPersona[id] ?? 0} endpoints`)
              .join(" · ")}
          </li>
        )}
        <li>
          Checks run: {ran.length ? ran.map((p) => PHASE_LABEL[p.name]).join(", ") : "none yet"}
        </li>
        {skipped.length > 0 && (
          <li>
            <b>Not checked</b> (not built yet, or out of v1):{" "}
            {skipped.map((p) => PHASE_LABEL[p.name]).join(", ")}. Zero findings says nothing about these.
          </li>
        )}
      </ul>
    </div>
  );
}

// v1 #2: any finished scan can be run again. A failed one gets a prominent
// "Retry scan"; a completed one a quieter "Run again". Both start a fresh
// scan of the same target (the old one stays as history) and open it.
function RetryButton({ scan }: { scan: Scan }) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const failed = scan.state !== "complete";

  async function retry() {
    setBusy(true);
    setError(null);
    try {
      const next = await api.retryScan(scan.id);
      router.push(`/scans/${next.id}`);
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : String(err));
      setBusy(false);
    }
  }

  return (
    <span style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 8 }}>
      {error && <span className="field-error" style={{ display: "inline" }}>{error}</span>}
      <button className={failed ? "btn-primary" : undefined} onClick={retry} disabled={busy}>
        {busy ? "Starting…" : failed ? "Retry scan" : "Run again"}
      </button>
    </span>
  );
}
