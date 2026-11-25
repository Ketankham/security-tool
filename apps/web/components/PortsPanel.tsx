"use client";

import { useId, useMemo, useState } from "react";
import { api, saveBlob } from "@/lib/api";
import {
  CDN_NOTE,
  PORTS_CAVEAT,
  PORT_RENDER_LIMIT,
  UNVERIFIED_HINT,
  filterPorts,
  hostsText,
  isUnverified,
  parsePortFilter,
  portLabel,
  portsToCsv,
  scriptIds,
  sortPorts,
  summarise,
  versionText,
} from "@/lib/ports";
import type { PortService } from "@/lib/types";
import { usePoll } from "@/lib/usePoll";

// Open ports and services found by the port scan (naabu finds the open TCP
// ports, nmap names the service on the Full profile). Shown only when rows
// exist or the scan asked for the tool, so ordinary scans see no extra card.
// A service name that is only guessed from the port number carries an
// "unverified" badge and is never presented as a finding.

const NO_CAPS = { textTransform: "none" } as const;

export function ServiceCell({ row }: { row: PortService }) {
  if (!row.service) return <span className="hint">—</span>;
  return (
    <>
      <span className="mono">{row.service}</span>{" "}
      {isUnverified(row) && (
        <span
          className="badge tone-muted"
          style={{ ...NO_CAPS, whiteSpace: "nowrap" }}
          title={UNVERIFIED_HINT}
        >
          unverified
        </span>
      )}
    </>
  );
}

// Script output is plain text from the target: it goes into a <pre> as a React
// text child (escaped), never as HTML.
export function ScriptsCell({ row }: { row: PortService }) {
  const ids = scriptIds(row);
  if (ids.length === 0) return <span className="hint">—</span>;
  return (
    <details className="ev">
      <summary style={{ whiteSpace: "nowrap" }}>
        {ids.length} script{ids.length === 1 ? "" : "s"}
      </summary>
      {ids.map((id) => (
        <div key={id} style={{ marginTop: 6 }}>
          <div className="mono" style={{ fontWeight: 600 }}>{id}</div>
          <pre className="block" style={{ maxHeight: 240, overflow: "auto", minWidth: 220 }}>
            {row.scripts[id]}
          </pre>
        </div>
      ))}
    </details>
  );
}

export function PortsPanel({
  scanId,
  running,
  enabled,
}: {
  scanId: string;
  running: boolean;
  // The scan asked for port scanning (scan.options.port_scan).
  enabled: boolean;
}) {
  const ports = usePoll(() => api.listScanPorts(scanId), 10000, running);
  const uid = useId();
  const [text, setText] = useState("");
  const [verifiedOnly, setVerifiedOnly] = useState(false);
  const [portText, setPortText] = useState("");
  const [downloadError, setDownloadError] = useState<string | null>(null);

  const all = useMemo(() => sortPorts(ports.data ?? []), [ports.data]);
  const filtered = useMemo(
    () => filterPorts(all, { text, verifiedOnly, ports: portText }),
    [all, text, verifiedOnly, portText],
  );
  const shown = filtered.slice(0, PORT_RENDER_LIMIT);
  const summary = useMemo(() => summarise(all), [all]);
  const portFilterInvalid = parsePortFilter(portText) === null;

  // Nothing to show for a scan that did not use the tool (also covers the
  // endpoint being absent or failing on an old API).
  if (all.length === 0 && !enabled) return null;

  const title = "Open ports and services";

  if (all.length === 0) {
    return (
      <div className="card" style={{ marginTop: 16 }} id="ports">
        <h2>{title}</h2>
        {ports.error ? (
          <div className="error-box">Could not load the ports: {ports.error}</div>
        ) : !ports.data ? (
          <div className="hint">Loading…</div>
        ) : running ? (
          <div className="empty">Results appear here once the port scan step has run.</div>
        ) : (
          <div className="empty">
            No open TCP ports were found among the ports scanned. The Activity log and the Tool runs
            above say which addresses were scanned, or why the step did not run.
          </div>
        )}
        <p className="hint">{PORTS_CAVEAT}</p>
      </div>
    );
  }

  function download() {
    setDownloadError(null);
    try {
      saveBlob(
        new Blob([portsToCsv(filtered)], { type: "text/csv;charset=utf-8" }),
        `scan-${scanId.slice(0, 8)}-ports.csv`,
      );
    } catch (e) {
      setDownloadError(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <div className="card" style={{ marginTop: 16 }} id="ports">
      <h2>{title}</h2>
      {ports.error && <div className="error-box">Could not refresh the ports: {ports.error}</div>}
      <p className="card-muted" style={{ marginTop: 0 }}>
        {summary.total} open port(s) on {summary.ips} address(es)
        {summary.unverified > 0 && <>, {summary.unverified} with a service name guessed from the port number</>}.
        Open ports are things to review, not findings by themselves.
      </p>

      <div className="row" style={{ marginBottom: 10, alignItems: "flex-end" }}>
        <div style={{ flex: 2 }}>
          <label htmlFor={`${uid}-text`}>Filter by address, host, service or product</label>
          <input
            id={`${uid}-text`}
            type="text"
            value={text}
            placeholder="e.g. ssh or 203.0.113.7"
            onChange={(e) => setText(e.target.value)}
          />
        </div>
        <div>
          <label htmlFor={`${uid}-ports`}>Ports</label>
          <input
            id={`${uid}-ports`}
            type="text"
            value={portText}
            placeholder="e.g. 22,80,8000-8100"
            aria-invalid={portFilterInvalid}
            aria-describedby={portFilterInvalid ? `${uid}-ports-err` : undefined}
            onChange={(e) => setPortText(e.target.value)}
          />
          {portFilterInvalid && (
            <div className="hint" id={`${uid}-ports-err`} role="alert">
              Use port numbers and ranges such as 22,80,8000-8100. Showing all ports.
            </div>
          )}
        </div>
        <div style={{ flex: "0 0 auto", minWidth: 0 }}>
          <label className="check-row" style={{ margin: "0 0 8px" }}>
            <input
              type="checkbox"
              checked={verifiedOnly}
              onChange={(e) => setVerifiedOnly(e.target.checked)}
            />
            Only verified services
          </label>
        </div>
        <div style={{ flex: "0 0 auto", minWidth: 0 }}>
          <button type="button" className="btn-sm" onClick={download} disabled={filtered.length === 0}>
            Download CSV
          </button>
        </div>
      </div>
      {downloadError && <div className="error-box">{downloadError}</div>}

      <div className="hint" role="status" aria-live="polite" style={{ marginBottom: 6 }}>
        showing {shown.length.toLocaleString()} of {all.length.toLocaleString()}
        {filtered.length !== all.length && <> ({filtered.length.toLocaleString()} match the filters)</>}
      </div>
      {filtered.length > PORT_RENDER_LIMIT && (
        <div className="notice" style={{ marginBottom: 8 }}>
          Showing the first {PORT_RENDER_LIMIT} of {filtered.length.toLocaleString()} matching rows.
          Download the CSV for all of them.
        </div>
      )}

      {filtered.length === 0 ? (
        <div className="empty">No ports match these filters.</div>
      ) : (
        <div style={{ overflowX: "auto" }}>
          <table className="report-table" aria-label={title}>
            <thead>
              <tr>
                <th scope="col">Address</th>
                <th scope="col">Port</th>
                <th scope="col" style={{ whiteSpace: "nowrap" }}>State</th>
                <th scope="col">Service</th>
                <th scope="col">Product and version</th>
                <th scope="col">Scripts</th>
                <th scope="col">CDN</th>
                <th scope="col">Found by</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((r) => (
                <tr key={r.id}>
                  <td className="mono" style={{ minWidth: 150 }}>
                    <div style={{ overflowWrap: "anywhere" }}>{r.ip}</div>
                    {r.hosts.length > 0 && (
                      <div className="hint" style={{ overflowWrap: "anywhere" }}>
                        {hostsText(r)}
                      </div>
                    )}
                  </td>
                  <td className="mono" style={{ whiteSpace: "nowrap" }}>{portLabel(r)}</td>
                  <td style={{ whiteSpace: "nowrap" }}>{r.state}</td>
                  <td>
                    <ServiceCell row={r} />
                  </td>
                  <td style={{ overflowWrap: "anywhere", minWidth: 140 }}>
                    {versionText(r) || <span className="hint">—</span>}
                  </td>
                  <td style={{ minWidth: 100 }}>
                    <ScriptsCell row={r} />
                  </td>
                  <td>
                    {r.cdn ? (
                      <>
                        <span className="badge tone-running" style={{ ...NO_CAPS, whiteSpace: "nowrap" }} title={CDN_NOTE}>
                          {r.cdn}
                        </span>
                        <div className="hint">Only ports 80 and 443 are checked on CDN addresses.</div>
                      </>
                    ) : (
                      <span className="hint">—</span>
                    )}
                  </td>
                  <td style={{ whiteSpace: "nowrap" }}>{r.found_by}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="hint">{PORTS_CAVEAT}</p>
    </div>
  );
}
