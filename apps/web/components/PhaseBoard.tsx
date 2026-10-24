"use client";

import { PHASE_ORDER, PHASE_STATUS_META } from "@/lib/scan";
import type { Scan, ScanPhase } from "@/lib/types";

// The centerpiece: every checkpoint of the scan lifecycle with its live
// status. Phase rows are driven by scan.phases when present and fall back to
// "pending" for phases the worker hasn't created a row for yet.
export function PhaseBoard({ scan }: { scan: Scan }) {
  const byName = new Map<string, ScanPhase>(scan.phases.map((p) => [p.name, p]));

  let parallelHeaderShown = false;

  return (
    <div className="phase-list">
      {PHASE_ORDER.map((meta) => {
        const phase = byName.get(meta.name);
        const status = phase?.status ?? "pending";
        const tone = PHASE_STATUS_META[status].tone;
        const active = status === "running";

        const showParallelHeader = meta.parallel && !parallelHeaderShown;
        if (meta.parallel) parallelHeaderShown = true;

        const stats = phase?.stats_json ?? {};
        const statKeys = Object.keys(stats);

        return (
          <div key={meta.name}>
            {showParallelHeader && (
              <div className="phase-parallel-label">Testing — runs in parallel</div>
            )}
            <div className={`phase${active ? " active" : ""}`}>
              <span className={`dot ${tone}`} />
              <div className="body">
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span className="name">{meta.label}</span>
                  <span className={`badge tone-${tone}`}>{PHASE_STATUS_META[status].label}</span>
                </div>
                <div className="blurb">{meta.blurb}</div>
                {phase?.error && <div className="err">{phase.error}</div>}
                {statKeys.length > 0 && (
                  <div className="hint" style={{ marginTop: 4 }}>
                    {statKeys.map((k) => `${k}: ${String((stats as Record<string, unknown>)[k])}`).join("  ·  ")}
                  </div>
                )}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
