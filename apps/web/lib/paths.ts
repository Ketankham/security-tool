// Pure helpers for the directory brute force results (PathsPanel + report).

import type { DiscoveredPath } from "./types";

export const PATH_RENDER_LIMIT = 500; // rows drawn at once on the scan page
export const REPORT_PATH_LIMIT = 1000; // rows drawn in the report; JSON has all

export const CATEGORY_LABEL: Record<string, string> = {
  config: "config",
  backup: "backup",
  vcs: "version control",
  admin: "admin",
  api: "api",
  common: "common",
};

export function categoryLabel(c: string): string {
  return CATEGORY_LABEL[c] ?? c;
}

/** Only http(s) URLs become links; anything else is shown as plain text. */
export function isHttpUrl(u: string): boolean {
  return /^https?:\/\//i.test(u);
}

export function statusTone(code: number): string {
  if (code >= 200 && code < 300) return "tone-ok";
  if (code >= 300 && code < 400) return "tone-running";
  if (code >= 500) return "tone-bad";
  return "tone-muted"; // 401/403/405 and anything unexpected
}

export function formatSize(n: number | null): string {
  if (n === null || n === undefined) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

export function findingAnchor(findingId: string): string {
  return `#finding-${findingId}`;
}

/** Verdict as plain text (used by the CSV and the report). */
export function verdictText(p: DiscoveredPath): string {
  if (p.verdict === "confirmed") return p.rule_id ? `Confirmed: ${p.rule_id}` : "Confirmed";
  if (p.verdict === "not_confirmed") return "Not confirmed";
  if (p.verdict === "found") return "Found";
  return p.verdict;
}

/** Confirmed rows first, otherwise the server's order (stable). */
export function confirmedFirst(rows: DiscoveredPath[]): DiscoveredPath[] {
  const confirmed = rows.filter((r) => r.verdict === "confirmed");
  const rest = rows.filter((r) => r.verdict !== "confirmed");
  return [...confirmed, ...rest];
}

export interface PathFilter {
  category: string; // "" = all
  confirmedOnly: boolean;
  text: string;
}

export function filterPaths(rows: DiscoveredPath[], f: PathFilter): DiscoveredPath[] {
  const needle = f.text.trim().toLowerCase();
  return rows.filter(
    (r) =>
      (!f.category || r.category === f.category) &&
      (!f.confirmedOnly || r.verdict === "confirmed") &&
      (!needle || r.path.toLowerCase().includes(needle)),
  );
}

// --- CSV --------------------------------------------------------------------

/** One CSV cell: always quoted, quotes doubled, and a cell that a spreadsheet
 * would read as a formula (starts with = + - @, tab or CR) gets a leading
 * single quote so it opens as text. */
export function csvCell(value: string | number | boolean | null | undefined): string {
  if (value === null || value === undefined) return '""';
  let s = String(value);
  if (typeof value === "string" && /^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return `"${s.replace(/"/g, '""')}"`;
}

const CSV_HEADER = [
  "host",
  "path",
  "url",
  "method",
  "status",
  "size_bytes",
  "content_type",
  "redirect_location",
  "category",
  "verdict",
  "rule_id",
  "finding_id",
  "note",
  "used_for_crawl",
  "wordlist",
];

export function pathsToCsv(rows: DiscoveredPath[]): string {
  const lines = [CSV_HEADER.map(csvCell).join(",")];
  for (const r of rows) {
    lines.push(
      [
        r.origin,
        r.path,
        r.url,
        r.method,
        r.status_code,
        r.content_length,
        r.content_type,
        r.redirect_location,
        r.category,
        r.verdict,
        r.rule_id,
        r.finding_id,
        r.note,
        r.crawl_seed ? "yes" : "no",
        r.wordlist,
      ]
        .map(csvCell)
        .join(","),
    );
  }
  // BOM so Excel reads UTF-8; CRLF line endings per RFC 4180.
  return "﻿" + lines.join("\r\n") + "\r\n";
}
