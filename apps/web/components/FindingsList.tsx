"use client";

import { SEVERITY_META, SEVERITY_ORDER } from "@/lib/scan";
import type { Finding, FindingSeverity } from "@/lib/types";

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

export function FindingsList({ findings }: { findings: Finding[] }) {
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
        <FindingRow key={f.id} finding={f} />
      ))}
    </div>
  );
}

function FindingRow({ finding: f }: { finding: Finding }) {
  const sev = SEVERITY_META[f.severity as FindingSeverity];
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
          Reproduced {f.verification.reproduced_count}/{f.verification.attempted_count}
          {f.verification.passed ? " — verification passed" : ""}
        </div>
      )}
      {f.evidence.length > 0 && (
        <details className="ev">
          <summary>{f.evidence.length} evidence item(s)</summary>
          <pre className="block">
            {f.evidence
              .map((e) => `[${e.role}] ${e.note}\n  transcript: ${e.transcript_id}`)
              .join("\n\n")}
          </pre>
        </details>
      )}
    </div>
  );
}
