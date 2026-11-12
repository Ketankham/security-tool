"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { use, useState } from "react";
import { OrgGate } from "../../OrgGate";
import { ApiError, api } from "@/lib/api";
import { usePoll } from "@/lib/usePoll";
import { STATE_LABEL, isFailureState, isTerminal } from "@/lib/scan";
import type { OwnershipChallenge, OwnershipMethod, Persona, Scan, ScopeRule, Target } from "@/lib/types";

export default function TargetPage({ params }: { params: Promise<{ targetId: string }> }) {
  const { targetId } = use(params);
  return (
    <OrgGate>
      <TargetDetail targetId={targetId} />
    </OrgGate>
  );
}

function TargetDetail({ targetId }: { targetId: string }) {
  const { data: target, error, refresh } = usePoll<Target>(() => api.getTarget(targetId), 20000);

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

          <OwnershipCard target={target} onChange={refresh} />
          <ScopeCard targetId={targetId} />
          <PersonasCard targetId={targetId} />
          <ScansCard target={target} />
        </>
      )}
    </>
  );
}

function OwnershipCard({ target, onChange }: { target: Target; onChange: () => void }) {
  const [method, setMethod] = useState<OwnershipMethod>("dns_txt");
  const [challenge, setChallenge] = useState<OwnershipChallenge | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [verifyMsg, setVerifyMsg] = useState<string | null>(null);

  async function getChallenge() {
    setBusy(true);
    setError(null);
    try {
      setChallenge(await api.ownershipChallenge(target.id, method));
    } catch (e) {
      setError(e instanceof ApiError ? e.detail : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function verify() {
    setBusy(true);
    setError(null);
    setVerifyMsg(null);
    try {
      const res = await api.ownershipVerify(target.id);
      setVerifyMsg(res.detail);
      if (res.verified) onChange();
    } catch (e) {
      setError(e instanceof ApiError ? e.detail : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function accept() {
    setBusy(true);
    setError(null);
    try {
      await api.acceptAuthorization(target.id);
      onChange();
    } catch (e) {
      setError(e instanceof ApiError ? e.detail : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card">
      <h2>
        Ownership & authorization{" "}
        {target.is_scannable ? (
          <span className="badge tone-ok">Ready</span>
        ) : (
          <span className="badge tone-pending">Incomplete</span>
        )}
      </h2>
      <p className="card-muted">
        We never scan a target until ownership is proven and testing is
        explicitly authorized. This gate is a safety requirement, not a
        formality.
      </p>

      {error && <div className="error-box" style={{ margin: "10px 0" }}>{error}</div>}

      {/* Step 1: ownership */}
      {!target.ownership_verified ? (
        <>
          <div className="inline-form" style={{ marginTop: 10 }}>
            <div>
              <label>Verification method</label>
              <select value={method} onChange={(e) => setMethod(e.target.value as OwnershipMethod)}>
                <option value="dns_txt">DNS TXT record</option>
                <option value="well_known_file">well-known file</option>
                <option value="meta_tag">HTML meta tag</option>
              </select>
            </div>
            <button disabled={busy} onClick={getChallenge}>
              Get challenge
            </button>
          </div>
          {challenge && (
            <div className="notice" style={{ marginTop: 12 }}>
              <strong>{challenge.instructions}</strong>
              <pre className="block">{challenge.token}</pre>
              <button className="btn-primary" style={{ marginTop: 10 }} disabled={busy} onClick={verify}>
                {busy ? "Checking…" : "I've done it — verify"}
              </button>
              {verifyMsg && <div className="hint" style={{ marginTop: 8 }}>{verifyMsg}</div>}
            </div>
          )}
        </>
      ) : (
        <div className="hint" style={{ marginTop: 8 }}>
          ✓ Ownership verified
          {target.ownership_verification_method ? ` via ${target.ownership_verification_method}` : ""}.
        </div>
      )}

      {/* Step 2: authorization */}
      {target.ownership_verified && !target.authorization_accepted && (
        <div style={{ marginTop: 14 }}>
          <button className="btn-primary" disabled={busy} onClick={accept}>
            Accept testing authorization
          </button>
          <div className="hint" style={{ marginTop: 6 }}>
            Confirms you own or are contractually authorized to test this target.
          </div>
        </div>
      )}
      {target.authorization_accepted && (
        <div className="hint" style={{ marginTop: 8 }}>✓ Testing authorized.</div>
      )}
    </div>
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
        <button className="btn-primary" disabled={busy || !target.is_scannable} onClick={run}>
          {busy ? "Starting…" : "Run scan"}
        </button>
        {!target.is_scannable && (
          <div className="hint" style={{ marginTop: 6 }}>
            Verify ownership and accept authorization above first.
          </div>
        )}
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
