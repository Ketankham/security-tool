"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { ApiError, api, downloadScanLog } from "@/lib/api";
import type { ScanEvent } from "@/lib/types";

// The scan's activity log (Step 1A): every stage, login attempt, page the
// crawler visited or skipped, and authorization comparison, with the reason.
// It's how a reviewer checks the scan really did what it says. Live while the
// scan runs (polls only events newer than the last one it holds), complete
// once it has finished. Secrets are redacted server-side.

const STAGE_LABEL: Record<string, string> = {
  scan: "Scan",
  scope: "Scope",
  recon: "Recon",
  dir_bruteforce: "Directory brute force",
  ports: "Ports & services",
  auth: "Logins",
  crawl: "Crawl",
  surface: "Surface",
  passive_checks: "Passive checks",
  access_control: "Authorization",
  injection: "Injection",
  session: "Session",
  business_logic: "Business logic",
  verify: "Verify",
  triage: "Triage",
  report: "Report",
};

const RENDER_LIMIT = 1500; // lines drawn at once; the download has everything

function time(at: string): string {
  const d = new Date(at);
  return Number.isNaN(d.getTime()) ? at : d.toLocaleTimeString([], { hour12: false });
}

export function ActivityLog({ scanId, running }: { scanId: string; running: boolean }) {
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [stage, setStage] = useState("");
  const [persona, setPersona] = useState("");
  const [problemsOnly, setProblemsOnly] = useState(false);
  const [stick, setStick] = useState(true);
  const [dlError, setDlError] = useState<string | null>(null);
  const lastSeq = useRef(0);
  const box = useRef<HTMLDivElement>(null);

  // Load everything so far, then keep fetching newer lines while the scan
  // runs; one extra fetch after it stops picks up the last lines.
  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;

    async function pull() {
      try {
        // Drain: a long scan can have more than one page waiting.
        for (;;) {
          const page = await api.listScanEvents(scanId, lastSeq.current);
          if (cancelled) return;
          setTotal(page.total);
          if (page.events.length === 0) break;
          lastSeq.current = page.last_seq;
          setEvents((prev) => [...prev, ...page.events]);
          if (page.events.length < 2000) break;
        }
        setError(null);
        setLoaded(true);
      } catch (e) {
        if (!cancelled) setError(e instanceof ApiError ? e.detail : String(e));
      }
      if (!cancelled && running) timer = setTimeout(pull, 2500);
    }

    void pull();
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, [scanId, running]);

  const stages = useMemo(() => Array.from(new Set(events.map((e) => e.stage))), [events]);
  const personas = useMemo(
    () => Array.from(new Set(events.map((e) => e.persona).filter((p): p is string => !!p))),
    [events],
  );
  const filtered = useMemo(
    () =>
      events.filter(
        (e) =>
          (!stage || e.stage === stage) &&
          (!persona || e.persona === persona) &&
          (!problemsOnly || e.level !== "info"),
      ),
    [events, stage, persona, problemsOnly],
  );
  const shown = filtered.slice(-RENDER_LIMIT);
  const problems = events.filter((e) => e.level !== "info").length;

  // Follow the newest line while the reader hasn't scrolled up.
  useEffect(() => {
    if (stick && box.current) box.current.scrollTop = box.current.scrollHeight;
  }, [shown.length, stick]);

  async function download() {
    setDlError(null);
    try {
      await downloadScanLog(scanId);
    } catch (e) {
      setDlError(e instanceof ApiError ? e.detail : String(e));
    }
  }

  return (
    <div className="card" style={{ marginTop: 16 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
        <h2 style={{ margin: 0 }}>Activity log</h2>
        {running && <span className="hint">live</span>}
        <span className="hint">
          {total} line{total === 1 ? "" : "s"}
          {problems > 0 && ` · ${problems} warning${problems === 1 ? "" : "s"}/error${problems === 1 ? "" : "s"}`}
        </span>
        <span style={{ marginLeft: "auto" }} />
        <button className="btn-sm" onClick={download} disabled={total === 0}>
          Download log
        </button>
      </div>
      <p className="card-muted" style={{ marginTop: 4 }}>
        Everything the scan did, in order: each stage, login, page visited or skipped (with the
        reason) and authorization comparison. Passwords, cookies and tokens are blanked out.
      </p>
      {error && <div className="error-box">{error}</div>}
      {dlError && <div className="error-box">{dlError}</div>}

      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", margin: "8px 0" }}>
        <select value={stage} onChange={(e) => setStage(e.target.value)} aria-label="Stage">
          <option value="">All stages</option>
          {stages.map((s) => (
            <option key={s} value={s}>
              {STAGE_LABEL[s] ?? s}
            </option>
          ))}
        </select>
        <select value={persona} onChange={(e) => setPersona(e.target.value)} aria-label="Identity">
          <option value="">All identities</option>
          {personas.map((p) => (
            <option key={p} value={p}>
              {p}
            </option>
          ))}
        </select>
        <label style={{ display: "flex", gap: 6, alignItems: "center" }}>
          <input
            type="checkbox"
            checked={problemsOnly}
            onChange={(e) => setProblemsOnly(e.target.checked)}
            style={{ width: "auto" }}
          />
          Warnings and errors only
        </label>
      </div>

      <div
        ref={box}
        role="log"
        aria-label="Scan activity log"
        onScroll={(e) => {
          const el = e.currentTarget;
          setStick(el.scrollHeight - el.scrollTop - el.clientHeight < 24);
        }}
        style={{
          maxHeight: 420,
          overflow: "auto",
          background: "var(--bg)",
          border: "1px solid var(--border)",
          borderRadius: 8,
          padding: 8,
          fontFamily: "var(--mono)",
          fontSize: 12.5,
          lineHeight: 1.55,
        }}
      >
        {!loaded && !error && <div className="hint">Loading…</div>}
        {loaded && events.length === 0 && (
          <div className="hint">
            No activity recorded for this scan. (Scans that ran before the activity log existed
            have none.)
          </div>
        )}
        {loaded && events.length > 0 && filtered.length === 0 && (
          <div className="hint">No lines match these filters.</div>
        )}
        {filtered.length > shown.length && (
          <div className="hint">
            Showing the last {shown.length} of {filtered.length} matching lines. Download the log
            for all of them.
          </div>
        )}
        {shown.map((e) => (
          <div
            key={e.seq}
            style={{
              display: "flex",
              gap: 8,
              color:
                e.level === "error" ? "var(--bad)" : e.level === "warn" ? "var(--warn)" : undefined,
            }}
          >
            <span style={{ color: "var(--text-faint)", flex: "none" }}>{time(e.at)}</span>
            <span style={{ color: "var(--accent)", flex: "none", minWidth: 92 }}>
              {STAGE_LABEL[e.stage] ?? e.stage}
            </span>
            {e.persona && <span style={{ color: "var(--text-dim)", flex: "none" }}>[{e.persona}]</span>}
            <span style={{ wordBreak: "break-word", minWidth: 0 }}>{e.message}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
