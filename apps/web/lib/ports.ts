// Pure helpers for the port scan results (PortsPanel + report).

import { csvCell } from "./csv";
import type { PortService } from "./types";

export const PORT_RENDER_LIMIT = 500; // rows drawn at once on the scan page
export const REPORT_PORT_LIMIT = 1000; // rows drawn in the report; JSON has all

/** Shown next to every service name that is only a guess. */
export const UNVERIFIED_HINT =
  "Guessed from the port number only. Nothing was sent to the port to identify the service, so it may be wrong.";

export const PORTS_CAVEAT =
  "Open means a TCP connection succeeded. Behind a proxy or firewall that answers for the host, ports can look open when they are not; service names marked unverified are guesses.";

export const CDN_NOTE =
  "This address belongs to a CDN, so only ports 80 and 443 were checked on it.";

/** A service name that is a guess from the port number, not something a tool identified. */
export function isUnverified(r: PortService): boolean {
  return r.confidence === "port_guess";
}

/** "443/tcp". */
export function portLabel(r: PortService): string {
  return `${r.port}/${r.protocol}`;
}

/** Product, version and extra info on one line ("" when none). */
export function versionText(r: PortService): string {
  const main = [r.product, r.version].filter((x): x is string => !!x && x.trim() !== "").join(" ");
  const extra = r.extra_info && r.extra_info.trim() !== "" ? `(${r.extra_info.trim()})` : "";
  return [main, extra].filter(Boolean).join(" ");
}

/** Service name for text output, with the guess marked. */
export function serviceText(r: PortService): string {
  if (!r.service) return "";
  return isUnverified(r) ? `${r.service} (unverified)` : r.service;
}

export function scriptIds(r: PortService): string[] {
  return Object.keys(r.scripts ?? {}).sort();
}

/** The host names for one row as a single plain string ("" when none). */
export function hostsText(r: PortService): string {
  return (r.hosts ?? []).join(", ");
}

// --- Port filter ("22, 80, 8000-8100") -------------------------------------

export type PortRange = [number, number];

/** Parses "22,80,8000-8100". Empty text gives []; invalid text gives null. */
export function parsePortFilter(text: string): PortRange[] | null {
  const t = text.trim();
  if (!t) return [];
  const out: PortRange[] = [];
  for (const part of t.split(/[\s,]+/).filter(Boolean)) {
    const m = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(part);
    if (!m) return null;
    const lo = Number(m[1]);
    const hi = m[2] === undefined ? lo : Number(m[2]);
    if (lo > 65535 || hi > 65535 || lo > hi) return null;
    out.push([lo, hi]);
  }
  return out;
}

export interface PortFilter {
  text: string; // ip / host / service / product
  verifiedOnly: boolean; // hide services that are only guessed from the port number
  ports: string; // "22,80,8000-8100" ("" = all); invalid text filters nothing
}

export function filterPorts(rows: PortService[], f: PortFilter): PortService[] {
  const needle = f.text.trim().toLowerCase();
  const ranges = parsePortFilter(f.ports) ?? [];
  return rows.filter((r) => {
    if (f.verifiedOnly && isUnverified(r)) return false;
    if (ranges.length > 0 && !ranges.some(([lo, hi]) => r.port >= lo && r.port <= hi)) return false;
    if (!needle) return true;
    const hay = [r.ip, ...(r.hosts ?? []), r.service ?? "", r.product ?? ""].join("\n").toLowerCase();
    return hay.includes(needle);
  });
}

// --- Sorting ----------------------------------------------------------------

function ipv4Key(ip: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  if (parts.some((n) => n > 255)) return null;
  return ((parts[0] * 256 + parts[1]) * 256 + parts[2]) * 256 + parts[3];
}

/** IPv4 addresses numerically (before anything else), the rest as text. */
export function compareIp(a: string, b: string): number {
  const ka = ipv4Key(a);
  const kb = ipv4Key(b);
  if (ka !== null && kb !== null) return ka - kb;
  if (ka !== null) return -1;
  if (kb !== null) return 1;
  return a < b ? -1 : a > b ? 1 : 0;
}

/** ip, then port, then protocol. The server already sorts this way; this keeps
 * the page correct if it ever does not. Returns a new array. */
export function sortPorts(rows: PortService[]): PortService[] {
  return [...rows].sort(
    (x, y) => compareIp(x.ip, y.ip) || x.port - y.port || (x.protocol < y.protocol ? -1 : x.protocol > y.protocol ? 1 : 0),
  );
}

// --- Summary ----------------------------------------------------------------

export function summarise(rows: PortService[]): { total: number; ips: number; unverified: number } {
  return {
    total: rows.length,
    ips: new Set(rows.map((r) => r.ip)).size,
    unverified: rows.filter(isUnverified).length,
  };
}

// --- CSV --------------------------------------------------------------------

// Script output is deliberately not exported: it can be long and is meant to
// be read on the scan page.
export const PORT_CSV_HEADER = [
  "ip",
  "hosts",
  "port",
  "protocol",
  "state",
  "service",
  "service_verified",
  "product",
  "version",
  "extra_info",
  "cdn",
  "found_by",
];

export function portCsvRow(r: PortService): (string | number | null)[] {
  return [
    r.ip,
    (r.hosts ?? []).join("; "),
    r.port,
    r.protocol,
    r.state,
    r.service,
    isUnverified(r) ? "no" : "yes",
    r.product,
    r.version,
    r.extra_info,
    r.cdn,
    r.found_by,
  ];
}

export function portsToCsv(rows: PortService[]): string {
  const lines = [PORT_CSV_HEADER.map(csvCell).join(",")];
  for (const r of rows) lines.push(portCsvRow(r).map(csvCell).join(","));
  // BOM so Excel reads UTF-8; CRLF line endings per RFC 4180.
  return "﻿" + lines.join("\r\n") + "\r\n";
}
