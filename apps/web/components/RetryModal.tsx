"use client";

import { useEffect, useId, useRef, useState } from "react";
import { ApiError, api } from "@/lib/api";
import { toolLabel } from "@/lib/activeTools";
import { useWhoami } from "@/lib/useWhoami";
import { AuthorisationBox } from "@/components/ActiveToolsFields";
import type { ActiveToolKey, Scan } from "@/lib/types";

// Shown when "Retry scan" answers 409: the scan used active tools, so a retry
// needs a fresh "I'm authorised" confirmation (the record must name whoever
// launches this traffic, now) or has to leave the active tools out.

export function RetryModal(props: {
  scan: Scan;
  tools: ActiveToolKey[];
  serverMessage: string;
  onClose: () => void;
  onStarted: (scanId: string) => void;
}) {
  const { scan, tools, serverMessage, onClose, onStarted } = props;
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;
  const titleId = useId();
  const idPrefix = useId();
  const { whoami, loading: whoamiLoading } = useWhoami();
  const [clientName, setClientName] = useState("");
  const [prefilled, setPrefilled] = useState(false);
  const [targetName, setTargetName] = useState("this target");
  const [accepted, setAccepted] = useState(false);
  const [allPortsConfirmed, setAllPortsConfirmed] = useState(false);
  const [busy, setBusy] = useState<"confirm" | "drop" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const dialogRef = useRef<HTMLDivElement>(null);
  const typedRef = useRef(false);

  const usesAllPorts = tools.includes("all_ports");
  const statement = whoami?.statement ?? null;
  const signedIn = !!whoami?.username;

  // Prefill the client from the previous authorisation, and learn the target's
  // name for the statement. Either can fail; the dialog still works.
  useEffect(() => {
    let alive = true;
    void Promise.allSettled([api.getScanAuthorisation(scan.id), api.getTarget(scan.target_id)]).then(
      ([authRes, targetRes]) => {
        if (!alive) return;
        if (authRes.status === "fulfilled" && !typedRef.current) {
          setClientName(authRes.value.client_name);
          setPrefilled(true);
        }
        if (targetRes.status === "fulfilled") setTargetName(targetRes.value.root_domain);
        else if (authRes.status === "fulfilled") setTargetName(authRes.value.target_name);
      },
    );
    return () => {
      alive = false;
    };
  }, [scan.id, scan.target_id]);

  // Escape closes; focus moves into the dialog and is kept inside it.
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    if (!dialogRef.current?.contains(document.activeElement)) dialogRef.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        onCloseRef.current();
        return;
      }
      if (e.key !== "Tab" || !dialogRef.current) return;
      const focusable = Array.from(
        dialogRef.current.querySelectorAll<HTMLElement>(
          'button, input, select, textarea, a[href], [tabindex]:not([tabindex="-1"])',
        ),
      ).filter((el) => !el.hasAttribute("disabled"));
      if (focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (e.shiftKey && (document.activeElement === first || document.activeElement === dialogRef.current)) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
      previous?.focus?.();
    };
  }, []);

  const client = clientName.trim();
  const canConfirm =
    signedIn && !!statement && !!client && accepted && (!usesAllPorts || allPortsConfirmed);
  const why = !signedIn
    ? "Sign-in required for active tools."
    : !statement
      ? "The authorisation statement could not be loaded."
      : !client
        ? "Name the client."
        : !accepted
          ? "Tick the confirmation."
          : usesAllPorts && !allPortsConfirmed
            ? "Tick the all-ports confirmation."
            : null;

  async function start(kind: "confirm" | "drop") {
    if (busy) return;
    if (kind === "confirm" && (!canConfirm || !statement)) return;
    setBusy(kind);
    setError(null);
    try {
      const next =
        kind === "confirm" && statement
          ? await api.retryScan(scan.id, {
              authorisation: {
                accepted: true,
                client_name: client,
                statement_version: statement.version,
                all_ports_confirmed: usesAllPorts ? allPortsConfirmed : false,
              },
            })
          : await api.retryScan(scan.id, { drop_active_tools: true });
      onStarted(next.id);
    } catch (e) {
      setError(e instanceof ApiError ? e.detail : String(e));
      setBusy(null);
    }
  }

  return (
    <div
      className="modal-backdrop"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget && !busy) onClose();
      }}
    >
      <div
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        ref={dialogRef}
      >
        <h2 id={titleId}>This scan used active tools</h2>
        <p style={{ margin: "0 0 6px" }}>{serverMessage}</p>
        <p className="hint" style={{ marginTop: 0 }}>
          Tools in the original scan: {tools.map(toolLabel).join(", ")}.
        </p>
        {error && (
          <div className="error-box" role="alert" style={{ marginBottom: 8 }}>
            {error}
          </div>
        )}

        {!signedIn && !whoamiLoading && (
          <div className="notice" role="status">
            Sign-in required for active tools. You can still retry without them.
          </div>
        )}
        {signedIn && statement && (
          <>
            {prefilled && (
              <div className="hint">Client name filled in from the previous confirmation.</div>
            )}
            <AuthorisationBox
              idPrefix={idPrefix}
              statement={statement}
              targetName={targetName}
              clientName={clientName}
              accepted={accepted}
              allPortsConfirmed={allPortsConfirmed}
              showAllPorts={usesAllPorts}
              onClientName={(v) => {
                typedRef.current = true;
                setClientName(v);
                setAccepted(false);
                setAllPortsConfirmed(false);
              }}
              onAccepted={setAccepted}
              onAllPortsConfirmed={setAllPortsConfirmed}
              autoFocus
            />
          </>
        )}
        {signedIn && !statement && !whoamiLoading && (
          <div className="error-box">The authorisation statement could not be loaded.</div>
        )}

        <div className="modal-actions">
          <button
            type="button"
            className="btn-primary"
            disabled={!canConfirm || busy !== null}
            title={why ?? undefined}
            onClick={() => start("confirm")}
          >
            {busy === "confirm" ? "Starting…" : "Confirm again"}
          </button>
          <button type="button" disabled={busy !== null} onClick={() => start("drop")}>
            {busy === "drop" ? "Starting…" : "Retry without active tools"}
          </button>
          <button type="button" disabled={busy !== null} onClick={onClose}>
            Close
          </button>
        </div>
        {why && signedIn && (
          <div className="hint" style={{ marginTop: 6 }}>
            {why}
          </div>
        )}
      </div>
    </div>
  );
}
