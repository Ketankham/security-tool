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

function humanise(key: string): string {
  const words = key
    .replace(/_(s|sec|secs|seconds)$/i, "")
    .replace(/[_-]+/g, " ")
    .trim();
  return words ? words.charAt(0).toUpperCase() + words.slice(1) : key;
}

export interface EstimateLine {
  label: string;
  value: string;
}

export function describeEstimate(estimate: unknown, maxDepth = 2): EstimateLine[] {
  const lines: EstimateLine[] = [];
  const walk = (obj: unknown, path: string[], depth: number) => {
    if (obj === null || typeof obj !== "object" || Array.isArray(obj)) return;
    for (const [key, val] of Object.entries(obj as Record<string, unknown>)) {
      const label = [...path, humanise(key)].join(" · ");
      if (typeof val === "number") {
        const isSeconds = /(^|_)(s|sec|secs|seconds)$/i.test(key);
        lines.push({
          label,
          value: isSeconds ? formatDuration(val) : val.toLocaleString(),
        });
      } else if (typeof val === "string" && val.length <= 80) {
        lines.push({ label, value: val });
      } else if (val && typeof val === "object" && depth < maxDepth) {
        walk(val, [...path, humanise(key)], depth + 1);
      }
    }
  };
  walk(estimate, [], 1);
  return lines;
}
