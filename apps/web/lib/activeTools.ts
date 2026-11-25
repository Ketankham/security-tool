// Pure helpers for the active-tools UI (directory brute force, port scan):
// labels, the authorisation statement, and rendering the API's estimate.

import type { ActiveToolKey, ScanOptions } from "./types";

export const ACTIVE_TOOL_LABEL: Record<ActiveToolKey, string> = {
  dir_bruteforce: "Directory brute force",
  port_scan: "Port scan",
  all_ports: "All 65,535 ports",
};

const ACTIVE_TOOL_KEYS: ActiveToolKey[] = ["dir_bruteforce", "port_scan", "all_ports"];

/** Human label for a tool key coming from the API (unknown keys pass through). */
export function toolLabel(key: string): string {
  return ACTIVE_TOOL_LABEL[key as ActiveToolKey] ?? key;
}

/** The active tools a scan's options switched on. */
export function activeToolsOf(options: ScanOptions | null | undefined): ActiveToolKey[] {
  if (!options) return [];
  return ACTIVE_TOOL_KEYS.filter((k) => options[k] === true);
}

/** Fills the {client} and {target} placeholders of a statement template. */
export function renderStatement(template: string, client: string, target: string): string {
  const c = client.trim() || "[client name]";
  return template.split("{client}").join(c).split("{target}").join(target);
}

// --- estimate ---------------------------------------------------------------
// sentinel_core.scan_options.estimate() returns a worst-case dict (per host and
// total). Its exact keys can evolve, so render it generically: numbers whose
// key says seconds become durations, other numbers are counted, short strings
// are shown as they are.

export function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return "n/a";
  if (seconds < 90) return `${Math.round(seconds)} s`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 90) return `${minutes} min`;
  const hours = Math.floor(minutes / 60);
  const rest = minutes % 60;
  return rest ? `${hours} h ${rest} min` : `${hours} h`;
}

export interface EstimateLine {
  label: string;
  value: string;
}

function num(obj: Record<string, unknown>, key: string): number | null {
  const v = obj[key];
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

function asRecord(v: unknown): Record<string, unknown> | null {
  return v !== null && typeof v === "object" && !Array.isArray(v)
    ? (v as Record<string, unknown>)
    : null;
}

// GET /scan-estimate: { dir_bruteforce, port_scan, all_ports (each null or a
// worst-case block), total_seconds }. Rendered as one plain sentence per tool
// that is switched on, plus the worst-case total. Missing or odd fields are
// skipped, never shown as NaN.
export function describeEstimate(estimate: unknown): EstimateLine[] {
  const root = asRecord(estimate);
  if (!root) return [];
  const lines: EstimateLine[] = [];

  const dir = asRecord(root.dir_bruteforce);
  if (dir) {
    const entries = num(dir, "entries");
    const hosts = num(dir, "max_hosts");
    const rps = num(dir, "requests_per_second");
    const perHost = num(dir, "seconds_per_host");
    const total = num(dir, "seconds_total");
    const parts: string[] = [];
    if (entries !== null && hosts !== null)
      parts.push(`${entries.toLocaleString()} paths on up to ${hosts} host${hosts === 1 ? "" : "s"}`);
    if (rps !== null) parts.push(`${rps}/s`);
    if (perHost !== null) parts.push(`about ${formatDuration(perHost)} per host`);
    if (total !== null) parts.push(`at most ${formatDuration(total)}`);
    if (parts.length) lines.push({ label: "Directory brute force", value: parts.join(", ") });
  }

  for (const [key, label, scope] of [
    ["port_scan", "Port scan", "top"],
    ["all_ports", "All 65,535 ports", "all"],
  ] as const) {
    const block = asRecord(root[key]);
    if (!block) continue;
    const ports = num(block, "ports_per_ip");
    const ips = num(block, "max_ips");
    const pps = num(block, "packets_per_second");
    const perIp = num(block, "seconds_per_ip");
    const total = num(block, "seconds_total");
    const parts: string[] = [];
    if (ports !== null && ips !== null)
      parts.push(
        `${scope === "top" ? "top " : ""}${ports.toLocaleString()} ports on up to ${ips} address${ips === 1 ? "" : "es"}`,
      );
    if (pps !== null) parts.push(`${pps} packets/s`);
    if (perIp !== null) parts.push(`about ${formatDuration(perIp)} per address`);
    if (total !== null) parts.push(`at most ${formatDuration(total)}`);
    if (parts.length) lines.push({ label, value: parts.join(", ") });
  }

  const total = num(root, "total_seconds");
  if (lines.length && total !== null) lines.push({ label: "Worst-case total", value: formatDuration(total) });
  return lines;
}
