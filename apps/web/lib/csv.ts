// Shared CSV helpers (paths and ports downloads).

/** One CSV cell: always quoted, quotes doubled, and a cell that a spreadsheet
 * would read as a formula (starts with = + - @, tab or CR) gets a leading
 * single quote so it opens as text. */
export function csvCell(value: string | number | boolean | null | undefined): string {
  if (value === null || value === undefined) return '""';
  let s = String(value);
  if (typeof value === "string" && /^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return `"${s.replace(/"/g, '""')}"`;
}
