"use client";

import { useState } from "react";
import { ApiError, api } from "@/lib/api";
import { SEVERITY_META, SEVERITY_ORDER } from "@/lib/scan";
import type { Evidence, Finding, FindingSeverity, TranscriptDoc } from "@/lib/types";

export function SeverityBar({ findings }: { findings: Finding[] }) {
  const counts = SEVERITY_ORDER.reduce<Record<string, number>>((acc, s) => {
    acc[s] = findings.filter((f) => f.severity === s).length;
    return acc;
  }, {});
  return (
    <div className="stat-row">
      {SEVERITY_ORDER.map((s) => (
        <div className="stat" key={s}>
          <span className="num" style={{ color: `var(--${SEVERITY_META[s].tone})` }}>
            {counts[s]}
          </span>
          <span className="lbl">{SEVERITY_META[s].label}</span>
        </div>
      ))}
    </div>
  );
}

export function FindingsList({
  findings,
  expanded = false,
}: {
  findings: Finding[];
  // Report view: every section open (a closed <details> does not print).
  expanded?: boolean;
}) {
  if (findings.length === 0) {
    return (
      <div className="empty">
        No findings yet. They appear here as checks confirm them — a confirmed
        finding must reproduce in the verification phase before it is listed.
      </div>
    );
  }

  const sorted = [...findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
  );

  return (
    <div className="list">
      {sorted.map((f) => (
        <FindingRow key={f.id} finding={f} expanded={expanded} />
      ))}
    </div>
  );
}

function asStrings(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
}

function FindingRow({ finding: f, expanded }: { finding: Finding; expanded: boolean }) {
  const sev = SEVERITY_META[f.severity as FindingSeverity];
  const summary = typeof f.remediation.summary === "string" ? f.remediation.summary : null;
  const steps = asStrings(f.remediation.steps);
  const curl = typeof f.reproduction.curl === "string" ? f.reproduction.curl : null;
  const expect = typeof f.reproduction.expect === "string" ? f.reproduction.expect : null;
  const url = typeof f.reproduction.url === "string" ? f.reproduction.url : null;
  return (
    <div className="list-item" style={{ alignItems: "flex-start", flexDirection: "column" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, width: "100%" }}>
        <span className={`badge ${sev.tone}`}>{sev.label}</span>
        <span className="grow title">{f.title}</span>
        <span className={`badge tone-${f.confidence === "confirmed" ? "ok" : "muted"}`}>
          {f.confidence}
        </span>
      </div>
      <div className="sub mono" style={{ marginTop: 4 }}>
        {f.rule_id}
        {f.owasp_top10 ? `  ·  ${f.owasp_top10}` : ""}
        {f.cwe.length ? `  ·  CWE-${f.cwe.join(", CWE-")}` : ""}
      </div>
      {f.narrative && <div className="sub" style={{ marginTop: 6 }}>{f.narrative}</div>}
      {f.verification && (
        <div className="hint" style={{ marginTop: 4 }}>
          Re-checked {f.verification.reproduced_count} of {f.verification.attempted_count} times
          {f.verification.passed ? " — reproduced, so it is confirmed" : ""}
        </div>
      )}
      {(summary || steps.length > 0) && (
        <details className="ev" style={{ width: "100%" }} open={expanded || undefined}>
          <summary>How to fix</summary>
          {summary && <p style={{ margin: "6px 0" }}>{summary}</p>}
          {steps.length > 0 && (
            <ol style={{ margin: "6px 0", paddingLeft: 20 }}>
              {steps.map((st, i) => (
                <li key={i}>{st}</li>
              ))}
            </ol>
          )}
        </details>
      )}
      {(curl || url) && (
        <details className="ev" style={{ width: "100%" }} open={expanded || undefined}>
          <summary>How to check it yourself</summary>
          {curl ? (
            <pre className="block">{curl}</pre>
          ) : (
            <pre className="block">{`GET ${url}`}</pre>
          )}
          {expect && <p style={{ margin: "6px 0" }}>{expect}</p>}
        </details>
      )}
      {f.evidence.length > 0 && (
        <details className="ev" style={{ width: "100%" }} open={expanded || undefined}>
          <summary>{f.evidence.length} evidence item(s): the exact requests and responses</summary>
          {f.evidence.map((e) => (
            <EvidenceItem key={`${e.transcript_id}-${e.role}`} scanId={f.scan_id} evidence={e} />
          ))}
        </details>
      )}
    </div>
  );
}

function headerLines(h?: Record<string, string>): string {
  return Object.entries(h ?? {})
    .map(([k, v]) => `${k}: ${v}`)
    .join("\n");
}

// One piece of evidence: what it shows, and (on demand) the stored request and
// response so a reviewer can check the claim by hand. Secrets are already
// blanked out in storage.
function EvidenceItem({ scanId, evidence }: { scanId: string; evidence: Evidence }) {
  const [doc, setDoc] = useState<TranscriptDoc | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function load() {
    setBusy(true);
    setError(null);
    try {
      setDoc(await api.getTranscript(scanId, evidence.transcript_id));
    } catch (e) {
      setError(e instanceof ApiError ? e.detail : String(e));
    } finally {
      setBusy(false);
    }
  }

  const req = doc?.request;
  const res = doc?.response;
  return (
    <div style={{ margin: "8px 0", paddingTop: 6, borderTop: "1px solid var(--border)" }}>
      <div>
        <span className="badge tone-muted">{evidence.role}</span>{" "}
        <span style={{ color: "var(--text-dim)" }}>{evidence.note}</span>
      </div>
      {!doc && (
        <button
          className="btn-sm no-print"
          style={{ marginTop: 6 }}
          onClick={load}
          disabled={busy}
        >
          {busy ? "Loading…" : "Show request and response"}
        </button>
      )}
      {error && <div className="error-box" style={{ marginTop: 6 }}>{error}</div>}
      {doc && (
        <pre className="block" style={{ marginTop: 6, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
          {`${req?.method ?? "GET"} ${req?.url ?? ""}\n${headerLines(req?.headers)}${
            req?.body ? `\n\n${req.body}` : ""
          }\n\n— response —\n${
            res
              ? `HTTP ${res.status_code}\n${headerLines(res.headers)}\n\n${res.body ?? ""}`
              : `no response${doc.error ? `: ${doc.error}` : ""}`
          }`}
        </pre>
      )}
    </div>
  );
}
