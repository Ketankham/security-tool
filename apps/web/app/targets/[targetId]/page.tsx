"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { use, useState } from "react";
import { OrgGate } from "../../OrgGate";
import { ApiError, api } from "@/lib/api";
import { usePoll } from "@/lib/usePoll";
import { STATE_LABEL, isFailureState, isTerminal } from "@/lib/scan";
import type { Persona, Scan, ScopeRule, Target } from "@/lib/types";

export default function TargetPage({ params }: { params: Promise<{ targetId: string }> }) {
  const { targetId } = use(params);
  return (
    <OrgGate>
      <TargetDetail targetId={targetId} />
    </OrgGate>
  );
}

function TargetDetail({ targetId }: { targetId: string }) {
  const { data: target, error } = usePoll<Target>(() => api.getTarget(targetId), 20000);

  return (
    <>
      <div className="crumbs">
        <Link href="/">Targets</Link> / {target?.display_name ?? targetId.slice(0, 8)}
      </div>

      {error && <div className="error-box">{error}</div>}
      {!target ? (
        <div className="notice">Loading target…</div>
      ) : (
        <>
          <h1>{target.display_name}</h1>
          <p className="card-muted mono">{target.root_domain}</p>

          <ScopeCard targetId={targetId} />
          <PersonasCard targetId={targetId} />
          <ScansCard target={target} />
        </>
      )}
    </>
  );
}

function ScopeCard({ targetId }: { targetId: string }) {
  const { data: rules, error, refresh } = usePoll<ScopeRule[]>(
    () => api.listScopeRules(targetId),
    30000,
  );
  const [kind, setKind] = useState("path_prefix");
  const [pattern, setPattern] = useState("");
  const [effect, setEffect] = useState("include");
  const [busy, setBusy] = useState(false);
  const [formErr, setFormErr] = useState<string | null>(null);

  async function add() {
    setBusy(true);
    setFormErr(null);
    try {
      await api.createScopeRule(targetId, { kind, pattern: pattern.trim(), effect, label: "" });
      setPattern("");
      refresh();
    } catch (e) {
      setFormErr(e instanceof ApiError ? e.detail : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card">
      <h2>Scope rules</h2>
      <p className="card-muted">
        Include/exclude rules bound what the scanner may touch. The scope guard
        enforces these at request time.
      </p>
      {error && <div className="error-box">{error}</div>}
      {formErr && <div className="error-box" style={{ marginBottom: 8 }}>{formErr}</div>}

      {rules && rules.length > 0 && (
        <div className="list" style={{ margin: "10px 0" }}>
          {rules.map((r) => (
            <div className="list-item" key={r.id}>
              <span className={`badge tone-${r.effect === "include" ? "ok" : "bad"}`}>{r.effect}</span>
              <span className="grow mono">{r.kind}: {r.pattern}</span>
            </div>
          ))}
        </div>
      )}

      <div className="inline-form">
        <div style={{ maxWidth: 160 }}>
          <label>Kind</label>
          <select value={kind} onChange={(e) => setKind(e.target.value)}>
            <option value="host">host</option>
            <option value="path_prefix">path_prefix</option>
            <option value="path_regex">path_regex</option>
            <option value="method">method</option>
          </select>
        </div>
        <div style={{ flex: 2 }}>
          <label>Pattern</label>
          <input value={pattern} placeholder="/api/" onChange={(e) => setPattern(e.target.value)} />
        </div>
        <div style={{ maxWidth: 140 }}>
          <label>Effect</label>
          <select value={effect} onChange={(e) => setEffect(e.target.value)}>
            <option value="include">include</option>
            <option value="exclude">exclude</option>
          </select>
        </div>
        <button disabled={busy || !pattern.trim()} onClick={add}>Add</button>
      </div>
    </div>
  );
}

function PersonasCard({ targetId }: { targetId: string }) {
  const { data: personas, error, refresh } = usePoll<Persona[]>(
    () => api.listPersonas(targetId),
    30000,
  );
  const [open, setOpen] = useState(false);

  return (
    <div className="card">
      <h2>Personas</h2>
      <p className="card-muted">
        Each persona is a login with a role and (optionally) a tenant. The
        authorization engine replays every persona&apos;s requests as every
        other identity to find who can reach what they shouldn&apos;t.
      </p>
      {error && <div className="error-box">{error}</div>}

      {personas && personas.length > 0 && (
        <div className="list" style={{ margin: "10px 0" }}>
          {personas.map((p) => (
            <div className="list-item" key={p.id}>
              <div className="grow">
                <div className="title">
                  {p.label} <span className="hint">({p.role_name}, trust {p.trust_rank})</span>
                </div>
                <div className="sub">
                  {p.tenant_key ? `tenant ${p.tenant_key}` : "no tenant"}
                  {p.login_strategy ? ` · ${p.login_strategy}` : ""}
                  {p.has_login_recipe ? " · has login recipe" : " · no login recipe"}
                </div>
              </div>
              {p.is_available ? (
                <span className="badge tone-ok">Available</span>
              ) : (
                <span className="badge tone-bad" title={p.unavailable_reason ?? ""}>
                  Unavailable
                </span>
              )}
            </div>
          ))}
        </div>
      )}

      {open ? (
        <AddPersona targetId={targetId} onDone={() => { setOpen(false); refresh(); }} onCancel={() => setOpen(false)} />
      ) : (
        <button onClick={() => setOpen(true)}>+ Add persona</button>
      )}
    </div>
  );
}

function AddPersona({
  targetId,
  onDone,
  onCancel,
}: {
  targetId: string;
  onDone: () => void;
  onCancel: () => void;
}) {
  const [label, setLabel] = useState("");
  const [role, setRole] = useState("");
  const [trust, setTrust] = useState(0);
  const [tenant, setTenant] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      const body: Record<string, unknown> = {
        label: label.trim(),
        role_name: role.trim(),
        trust_rank: trust,
        tenant_key: tenant.trim() || null,
        expected_denied: [],
      };
      if (password.trim()) {
        body.login_strategy = "form";
        body.credential = { kind: "password", secret: password };
      }
      await api.createPersona(targetId, body);
      onDone();
    } catch (e) {
      setError(e instanceof ApiError ? e.detail : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div style={{ borderTop: "1px solid var(--border)", marginTop: 12, paddingTop: 12 }}>
      {error && <div className="error-box" style={{ marginBottom: 8 }}>{error}</div>}
      <div className="row">
        <div>
          <label>Label</label>
          <input value={label} placeholder="Admin user" onChange={(e) => setLabel(e.target.value)} />
        </div>
        <div>
          <label>Role name</label>
          <input value={role} placeholder="admin" onChange={(e) => setRole(e.target.value)} />
        </div>
      </div>
      <div className="row">
        <div style={{ maxWidth: 140 }}>
          <label>Trust rank</label>
          <input
            type="number"
            min={0}
            value={trust}
            onChange={(e) => setTrust(Number(e.target.value))}
          />
        </div>
        <div>
          <label>Tenant key (optional)</label>
          <input value={tenant} placeholder="tenant-a" onChange={(e) => setTenant(e.target.value)} />
        </div>
      </div>
      <div className="row">
        <div>
          <label>Username (optional)</label>
          <input value={username} autoComplete="off" onChange={(e) => setUsername(e.target.value)} />
        </div>
        <div>
          <label>Password (optional, stored encrypted)</label>
          <input type="password" value={password} autoComplete="new-password" onChange={(e) => setPassword(e.target.value)} />
        </div>
      </div>
      <div className="hint" style={{ marginTop: 6 }}>
        A full login recipe (the exact steps to log in) is recorded separately;
        a password here seeds a form-login credential.
      </div>
      <div className="row" style={{ marginTop: 12 }}>
        <button className="btn-primary" disabled={busy || !label.trim() || !role.trim()} onClick={submit}>
          {busy ? "Saving…" : "Save persona"}
        </button>
        <button onClick={onCancel}>Cancel</button>
      </div>
    </div>
  );
}

function ScansCard({ target }: { target: Target }) {
  const router = useRouter();
  const { data: scans, error, refresh } = usePoll<Scan[]>(
    () => api.listScans(target.id),
    10000,
  );
  const [busy, setBusy] = useState(false);
  const [startErr, setStartErr] = useState<string | null>(null);

  async function run() {
    setBusy(true);
    setStartErr(null);
    try {
      const scan = await api.createScan(target.id);
      router.push(`/scans/${scan.id}`);
    } catch (e) {
      setStartErr(e instanceof ApiError ? e.detail : String(e));
      setBusy(false);
      refresh();
    }
  }

  return (
    <div className="card">
      <h2>Scans</h2>
      {error && <div className="error-box">{error}</div>}
      {startErr && <div className="error-box" style={{ marginBottom: 8 }}>{startErr}</div>}

      <div style={{ margin: "8px 0 14px" }}>
        <button className="btn-primary" disabled={busy} onClick={run}>
          {busy ? "Starting…" : "Run scan"}
        </button>
      </div>

      {scans && scans.length === 0 && <div className="empty">No scans yet.</div>}
      {scans && scans.length > 0 && (
        <div className="list">
          {scans
            .slice()
            .sort((a, b) => (b.started_at ?? "").localeCompare(a.started_at ?? ""))
            .map((s) => (
              <Link key={s.id} href={`/scans/${s.id}`} className="list-item" style={{ color: "inherit" }}>
                <div className="grow">
                  <div className="title mono">{s.id.slice(0, 8)}</div>
                  <div className="sub">
                    {s.triggered_by}
                    {s.started_at ? ` · started ${new Date(s.started_at).toLocaleString()}` : ""}
                  </div>
                </div>
                <ScanStateBadge state={s.state} />
              </Link>
            ))}
        </div>
      )}
    </div>
  );
}

function ScanStateBadge({ state }: { state: Scan["state"] }) {
  const tone = isFailureState(state) ? "bad" : state === "complete" ? "ok" : isTerminal(state) ? "muted" : "running";
  return <span className={`badge tone-${tone}`}>{STATE_LABEL[state]}</span>;
}
