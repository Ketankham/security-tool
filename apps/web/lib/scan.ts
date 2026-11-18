// Presentation metadata for the scan lifecycle. The canonical phase order
// and grouping mirror sentinel_core.state_machine (docs/01 §5, docs/02).

import type { FindingSeverity, PhaseName, PhaseStatus, Scan, ScanState } from "./types";

export interface PhaseMeta {
  name: PhaseName;
  label: string;
  // Short description of what this checkpoint proves.
  blurb: string;
  // The testing phases run concurrently once passive checks finish.
  parallel?: boolean;
}

// Ordered the way a scan actually walks them.
export const PHASE_ORDER: PhaseMeta[] = [
  { name: "scope_verifying", label: "Scope & ownership", blurb: "Confirm we're allowed to test this target and pin the in-scope surface." },
  { name: "recon", label: "Recon", blurb: "Subdomain discovery, DNS resolution, HTTP probing." },
  { name: "auth_establishing", label: "Authentication", blurb: "Log in as each persona and prove the session is live (login/onboarding)." },
  { name: "crawling", label: "Crawl", blurb: "Render each persona's reachable surface with a real browser." },
  { name: "surface_mapping", label: "Surface mapping", blurb: "Classify endpoints, parameters, and object references per persona." },
  { name: "passive_checks", label: "Passive & config", blurb: "Headers, cookies, CORS, TLS, info disclosure, exposed files." },
  { name: "active_injection", label: "Injection", blurb: "XSS, SQLi, SSRF, traversal, open redirect, SSTI — with deterministic oracles.", parallel: true },
  { name: "access_control", label: "Authorization", blurb: "Vertical/horizontal/IDOR/mass-assignment — the role-escalation checks.", parallel: true },
  { name: "session_checks", label: "Session management", blurb: "Logout invalidation, JWT handling, fixation, cookie lifetime.", parallel: true },
  { name: "business_logic", label: "Business logic", blurb: "Deferred to v1.5 — skipped in v1.", parallel: true },
  { name: "verifying", label: "Verification", blurb: "Re-run every candidate ≥2× — confirmed findings must reproduce." },
  { name: "triaging", label: "Triage", blurb: "Dedup, cluster, severity and CVSS." },
  { name: "reporting", label: "Report", blurb: "Assemble the final report: dashboard, PDF, SARIF." },
];

export const PHASE_LABEL: Record<PhaseName, string> = Object.fromEntries(
  PHASE_ORDER.map((p) => [p.name, p.label]),
) as Record<PhaseName, string>;

export const STATE_LABEL: Record<ScanState, string> = {
  queued: "Queued",
  scope_verifying: "Verifying scope",
  blocked_unverified: "Blocked — not verified",
  recon: "Recon",
  auth_establishing: "Authenticating",
  failed_auth: "Authentication failed",
  crawling: "Crawling",
  surface_mapping: "Mapping surface",
  passive_checks: "Passive checks",
  testing: "Testing",
  verifying: "Verifying",
  triaging: "Triaging",
  reporting: "Reporting",
  complete: "Complete",
  paused: "Paused",
  cancelled: "Cancelled",
  failed: "Failed",
};

const TERMINAL: ScanState[] = [
  "complete",
  "cancelled",
  "failed",
  "blocked_unverified",
  "failed_auth",
];

export function isTerminal(state: ScanState): boolean {
  return TERMINAL.includes(state);
}

export function isFailureState(state: ScanState): boolean {
  return ["failed", "cancelled", "blocked_unverified", "failed_auth"].includes(state);
}

export const PHASE_STATUS_META: Record<PhaseStatus, { label: string; tone: string }> = {
  pending: { label: "Pending", tone: "pending" },
  running: { label: "Running", tone: "running" },
  completed: { label: "Done", tone: "ok" },
  failed: { label: "Failed", tone: "bad" },
  skipped: { label: "Skipped", tone: "muted" },
};

export const SEVERITY_ORDER: FindingSeverity[] = ["critical", "high", "medium", "low", "info"];

export const SEVERITY_META: Record<FindingSeverity, { label: string; tone: string }> = {
  critical: { label: "Critical", tone: "sev-critical" },
  high: { label: "High", tone: "sev-high" },
  medium: { label: "Medium", tone: "sev-medium" },
  low: { label: "Low", tone: "sev-low" },
  info: { label: "Info", tone: "sev-info" },
};

// --- coverage (QA #38) -----------------------------------------------------------
// A scan that "completes" with most checks skipped must not read as clean.

/** The scan's status for display: a complete scan in which any check was
 * skipped (or that ran degraded) is "Complete · partial". */
export function scanStatus(scan: Pick<Scan, "state" | "phases" | "is_degraded">): {
  label: string;
  tone: string;
} {
  if (isFailureState(scan.state)) return { label: STATE_LABEL[scan.state], tone: "bad" };
  if (scan.state === "complete") {
    const partial = scan.is_degraded || scan.phases.some((p) => p.status === "skipped");
    return partial
      ? { label: "Complete · partial", tone: "running" }
      : { label: "Complete", tone: "ok" };
  }
  if (isTerminal(scan.state)) return { label: STATE_LABEL[scan.state], tone: "muted" };
  return { label: STATE_LABEL[scan.state], tone: "running" };
}

/** Phases that test for vulnerabilities (as opposed to set-up phases). */
export const CHECK_PHASES: PhaseName[] = [
  "passive_checks",
  "active_injection",
  "access_control",
  "session_checks",
  "business_logic",
];

export function crawlStats(scan: Scan): { pagesByPersona: Record<string, number>; endpointsByPersona: Record<string, number> } {
  const crawl = scan.phases.find((p) => p.name === "crawling");
  const stats = (crawl?.stats_json ?? {}) as Record<string, unknown>;
  return {
    pagesByPersona: (stats.pages_visited_by_persona as Record<string, number>) ?? {},
    endpointsByPersona: (stats.endpoints_by_persona as Record<string, number>) ?? {},
  };
}
