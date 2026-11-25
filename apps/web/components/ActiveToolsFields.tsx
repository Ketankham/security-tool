"use client";

import { useEffect, useId, useState } from "react";
import { api } from "@/lib/api";
import { describeEstimate, renderStatement, type EstimateLine } from "@/lib/activeTools";
import type {
  ReconProfile,
  ScanCreateBody,
  ScanDepth,
  ScanEstimate,
  ScanSpeed,
  Target,
  TargetEnvironment,
  Whoami,
  Wordlist,
} from "@/lib/types";

// Active tools (directory brute force, port scan, all ports) for the Run scan
// panel. They send extra traffic, so they need three things the passive scan
// does not: a verified signed-in user (the API refuses otherwise), the tool
// being offered by this deployment (/whoami.available_tools), and an
// "I'm authorised" confirmation that the server records against the scan.
//
// Only tools listed in available_tools are drawn; when none are, this renders
// nothing at all.

export interface ActiveToolsState {
  dirBruteforce: boolean;
  portScan: boolean;
  allPorts: boolean;
  wordlist: Wordlist;
  environment: TargetEnvironment;
  clientName: string;
  accepted: boolean;
  allPortsConfirmed: boolean;
}

export interface ActiveToolsContext {
  whoami: Whoami | null;
  reconProfile: ReconProfile;
}

/** Defaults: nothing ticked; environment follows the target's production flag. */
export function initialActiveTools(target: Pick<Target, "is_production">): ActiveToolsState {
  return {
    dirBruteforce: false,
    portScan: false,
    allPorts: false,
    wordlist: "sentinel-core",
    environment: target.is_production ? "production" : "staging",
    clientName: "",
    accepted: false,
    allPortsConfirmed: false,
  };
}

/** Which tools will actually be requested, after the rules the API enforces. */
export function effectiveTools(state: ActiveToolsState, ctx: ActiveToolsContext) {
  const available = new Set(ctx.whoami?.available_tools ?? []);
  const signedIn = !!ctx.whoami?.username;
  const full = ctx.reconProfile === "full";
  const dir = signedIn && available.has("dir_bruteforce") && state.dirBruteforce;
  const port = signedIn && available.has("port_scan") && state.portScan;
  const all = port && available.has("all_ports") && full && state.allPorts;
  const wordlist: Wordlist = dir && full ? state.wordlist : "sentinel-core";
  return { dir, port, all, wordlist, any: dir || port, available, signedIn, full };
}

/** Returns the same object when nothing needs correcting (so effects settle). */
function normalise(state: ActiveToolsState, ctx: ActiveToolsContext): ActiveToolsState {
  const t = effectiveTools(state, ctx);
  const next: ActiveToolsState = {
    ...state,
    dirBruteforce: state.dirBruteforce && t.dir,
    portScan: state.portScan && t.port,
    allPorts: state.allPorts && t.all,
    wordlist: t.wordlist,
    allPortsConfirmed: t.all ? state.allPortsConfirmed : false,
    accepted: t.any ? state.accepted : false,
  };
  const same =
    next.dirBruteforce === state.dirBruteforce &&
    next.portScan === state.portScan &&
    next.allPorts === state.allPorts &&
    next.wordlist === state.wordlist &&
    next.allPortsConfirmed === state.allPortsConfirmed &&
    next.accepted === state.accepted;
  return same ? state : next;
}

/** Why Start must stay disabled, or null when the active-tools part is valid. */
export function activeToolsProblem(state: ActiveToolsState, ctx: ActiveToolsContext): string | null {
  const t = effectiveTools(state, ctx);
  if (!t.any) return null;
  if (!ctx.whoami?.statement) return "The authorisation statement could not be loaded.";
  const client = state.clientName.trim();
  if (!client) return "Name the client to use active tools.";
  if (client.length > 200) return "The client name is too long (200 characters at most).";
  if (!state.accepted) return "Tick the authorisation confirmation to use active tools.";
  if (t.all && !state.allPortsConfirmed) return "Tick the separate confirmation for all 65,535 ports.";
  return null;
}

/** The extra fields for POST /targets/{id}/scans ({} when no tool is on). */
export function activeToolsPayload(
  state: ActiveToolsState,
  ctx: ActiveToolsContext,
): Partial<ScanCreateBody> {
  const t = effectiveTools(state, ctx);
  if (!t.any || !ctx.whoami?.statement) return {};
  return {
    dir_bruteforce: t.dir,
    port_scan: t.port,
    all_ports: t.all,
    wordlist: t.wordlist,
    target_environment: state.environment,
    authorisation: {
      accepted: state.accepted,
      client_name: state.clientName.trim(),
      statement_version: ctx.whoami.statement.version,
      all_ports_confirmed: t.all ? state.allPortsConfirmed : false,
    },
  };
}

const WORDLISTS: { value: Wordlist; label: string }[] = [
  { value: "sentinel-core", label: "Sentinel core: configs, backups, admin and API paths (up to 1,500)" },
  { value: "seclists-common", label: "SecLists common: general web paths (up to 4,751)" },
];

const ENVIRONMENTS: { value: TargetEnvironment; label: string }[] = [
  { value: "production", label: "Production: safe scripts only" },
  { value: "staging", label: "Staging: default scripts (more intrusive)" },
];

// --- the authorisation box (also used by the Retry dialog) -----------------------

export function AuthorisationBox(props: {
  idPrefix: string;
  statement: { template: string; all_ports_template: string };
  targetName: string;
  clientName: string;
  accepted: boolean;
  allPortsConfirmed: boolean;
  showAllPorts: boolean;
  onClientName: (v: string) => void;
  onAccepted: (v: boolean) => void;
  onAllPortsConfirmed: (v: boolean) => void;
  autoFocus?: boolean;
}) {
  const { idPrefix, statement, targetName, clientName } = props;
  const hasClient = clientName.trim().length > 0;
  return (
    <fieldset
      style={{
        border: "1px solid var(--border)",
        borderRadius: "var(--radius-sm)",
        margin: "10px 0 0",
        padding: "4px 12px 12px",
      }}
    >
      <legend style={{ padding: "0 6px", fontSize: "0.85rem", color: "var(--text-dim)" }}>
        Authorisation
      </legend>
      <label htmlFor={`${idPrefix}-client`}>Client name *</label>
      <input
        id={`${idPrefix}-client`}
        value={clientName}
        maxLength={200}
        autoFocus={props.autoFocus}
        placeholder="Who authorised this testing"
        onChange={(e) => props.onClientName(e.target.value)}
      />
      <label className="check-row">
        <input
          type="checkbox"
          checked={props.accepted}
          disabled={!hasClient}
          onChange={(e) => props.onAccepted(e.target.checked)}
        />
        <span>{renderStatement(statement.template, clientName, targetName)}</span>
      </label>
      {props.showAllPorts && (
        <label className="check-row">
          <input
            type="checkbox"
            checked={props.allPortsConfirmed}
            disabled={!hasClient}
            onChange={(e) => props.onAllPortsConfirmed(e.target.checked)}
          />
          <span>{renderStatement(statement.all_ports_template, clientName, targetName)}</span>
        </label>
      )}
      {!hasClient && (
        <div className="hint" style={{ marginTop: 6 }}>
          Enter the client name to enable the confirmation.
        </div>
      )}
      <div className="hint" style={{ marginTop: 6 }}>
        Your sign-in name, the time, the client and this exact wording are saved with the scan.
      </div>
    </fieldset>
  );
}

// --- the fields ----------------------------------------------------------------

export function ActiveToolsFields(props: {
  target: Pick<Target, "root_domain" | "is_production">;
  whoami: Whoami | null;
  reconProfile: ReconProfile;
  speed: ScanSpeed;
  depth: ScanDepth;
  value: ActiveToolsState;
  onChange: (next: ActiveToolsState) => void;
}) {
  const { target, whoami, reconProfile, speed, depth, value, onChange } = props;
  const uid = useId();
  const ctx: ActiveToolsContext = { whoami, reconProfile };
  const t = effectiveTools(value, ctx);

  // Keep the state valid when something else changes (recon profile back to
  // Light drops "all ports" and its tick; sign-in lost drops everything).
  useEffect(() => {
    const next = normalise(value, { whoami, reconProfile });
    if (next !== value) onChange(next);
  }, [value, whoami, reconProfile, onChange]);

  // Worst-case estimate from the API, refreshed when the choices change.
  const estimateKey = t.any
    ? JSON.stringify({
        speed,
        depth,
        recon_profile: reconProfile,
        dir_bruteforce: t.dir,
        port_scan: t.port,
        all_ports: t.all,
        wordlist: t.wordlist,
        target_environment: value.environment,
      })
    : null;
  const [estimate, setEstimate] = useState<ScanEstimate | null>(null);
  const [estimateFailed, setEstimateFailed] = useState(false);
  useEffect(() => {
    if (!estimateKey) {
      setEstimate(null);
      setEstimateFailed(false);
      return;
    }
    let alive = true;
    setEstimateFailed(false);
    const timer = setTimeout(() => {
      api
        .scanEstimate(JSON.parse(estimateKey) as Record<string, string | boolean>)
        .then((e) => {
          if (alive) setEstimate(e);
        })
        .catch(() => {
          if (alive) {
            setEstimate(null);
            setEstimateFailed(true);
          }
        });
    }, 250);
    return () => {
      alive = false;
      clearTimeout(timer);
    };
  }, [estimateKey]);

  // Nothing offered by this deployment (or /whoami failed): show nothing.
  const offers = (key: string) => t.available.has(key);
  if (!offers("dir_bruteforce") && !offers("port_scan") && !offers("all_ports")) return null;

  const set = (patch: Partial<ActiveToolsState>) => onChange({ ...value, ...patch });
  const locked = !t.signedIn;
  const estimateLines: EstimateLine[] = estimate ? describeEstimate(estimate) : [];

  return (
    <section
      aria-label="Active tools"
      style={{ borderTop: "1px solid var(--border)", marginTop: 12, paddingTop: 10 }}
    >
      <h3 style={{ marginBottom: 2 }}>Active tools</h3>
      <p className="hint" style={{ margin: "0 0 6px" }}>
        These send extra requests beyond a normal scan. Use them only with the client&apos;s written
        authorisation.
      </p>
      {locked && (
        <div className="notice" role="status" style={{ marginBottom: 8 }}>
          Sign-in required for active tools
        </div>
      )}

      {offers("dir_bruteforce") && (
        <label className="check-row">
          <input
            type="checkbox"
            checked={value.dirBruteforce}
            disabled={locked}
            onChange={(e) => set({ dirBruteforce: e.target.checked })}
          />
          <span>
            Directory brute force
            <span className="hint"> — tries common file and folder names (.env, backups, admin pages)</span>
          </span>
        </label>
      )}
      {offers("port_scan") && (
        <label className="check-row">
          <input
            type="checkbox"
            checked={value.portScan}
            disabled={locked}
            onChange={(e) => set({ portScan: e.target.checked })}
          />
          <span>
            Port scan
            <span className="hint"> — finds open TCP ports (top 1,000) on the target&apos;s addresses</span>
          </span>
        </label>
      )}
      {offers("all_ports") && (
        <label className="check-row">
          <input
            type="checkbox"
            checked={value.allPorts}
            disabled={locked || !t.port || !t.full}
            onChange={(e) => set({ allPorts: e.target.checked })}
          />
          <span>
            All 65,535 ports
            <span className="hint">
              {" "}
              — needs port scan on and the Full recon profile
              {t.port && !t.full ? " (switch Recon to Full)" : ""}
            </span>
          </span>
        </label>
      )}

      {t.any && (
        <>
          <div className="row">
            {offers("dir_bruteforce") && t.dir && (
              <div>
                <label htmlFor={`${uid}-wordlist`}>Wordlist</label>
                <select
                  id={`${uid}-wordlist`}
                  value={t.wordlist}
                  disabled={!t.full}
                  onChange={(e) => set({ wordlist: e.target.value as Wordlist })}
                >
                  {WORDLISTS.map((w) => (
                    <option key={w.value} value={w.value} disabled={!t.full && w.value !== "sentinel-core"}>
                      {w.label}
                    </option>
                  ))}
                </select>
                {!t.full && (
                  <div className="hint">The larger list needs the Full recon profile.</div>
                )}
              </div>
            )}
            <div>
              <label htmlFor={`${uid}-env`}>Environment</label>
              <select
                id={`${uid}-env`}
                value={value.environment}
                onChange={(e) => set({ environment: e.target.value as TargetEnvironment })}
              >
                {ENVIRONMENTS.map((o) => (
                  <option key={o.value} value={o.value}>
                    {o.label}
                  </option>
                ))}
              </select>
              <div className="hint">
                Preset from this target being {target.is_production ? "marked production" : "not production"}.
              </div>
            </div>
          </div>

          <div className="notice" style={{ marginTop: 10 }} aria-live="polite">
            <strong>Estimate (worst case)</strong>
            {estimateFailed && <div className="hint">The estimate is unavailable right now.</div>}
            {!estimate && !estimateFailed && <div className="hint">Calculating…</div>}
            {estimate && estimateLines.length === 0 && (
              <div className="hint">No estimate returned.</div>
            )}
            {estimateLines.length > 0 && (
              <ul style={{ margin: "4px 0 0", paddingLeft: 18 }}>
                {estimateLines.map((l) => (
                  <li key={l.label}>
                    {l.label}: <span className="mono">{l.value}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>

          {whoami?.statement ? (
            <AuthorisationBox
              idPrefix={uid}
              statement={whoami.statement}
              targetName={target.root_domain}
              clientName={value.clientName}
              accepted={value.accepted}
              allPortsConfirmed={value.allPortsConfirmed}
              showAllPorts={t.all}
              // Changing the client name changes the statement: confirm it again.
              onClientName={(v) => set({ clientName: v, accepted: false, allPortsConfirmed: false })}
              onAccepted={(v) => set({ accepted: v })}
              onAllPortsConfirmed={(v) => set({ allPortsConfirmed: v })}
            />
          ) : (
            <div className="error-box" style={{ marginTop: 10 }}>
              The authorisation statement could not be loaded, so active tools can&apos;t be started.
              Reload the page.
            </div>
          )}
        </>
      )}
    </section>
  );
}
