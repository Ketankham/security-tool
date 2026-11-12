"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { use, useEffect, useState } from "react";
import { OrgGate } from "../../OrgGate";
import { ApiError, api } from "@/lib/api";
import { usePoll } from "@/lib/usePoll";
import { STATE_LABEL, isFailureState, isTerminal } from "@/lib/scan";
import type { OwnershipChallenge, OwnershipMethod, Persona, Scan, ScopeRule, Target } from "@/lib/types";
import {
  EMPTY_LOGIN,
  LoginRecipeFields,
  buildLogin,
  loginFormFromRecipe,
  type LoginForm,
} from "@/components/LoginRecipeFields";

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

      {error && !target ? (
        <div className="card">
          <h2>Target not found</h2>
          <p className="card-muted">
            This target doesn&apos;t exist, or it belongs to a different organization. ({error})
          </p>
          <Link href="/">← Back to targets</Link>
        </div>
      ) : !target ? (
        <div className="notice">Loading target…</div>
      ) : (
        <>
          {error && <div className="error-box">{error}</div>}
          <h1>{target.display_name}</h1>
          <p className="card-muted mono">{target.root_domain}</p>

          <OwnershipCard target={target} onChange={refresh} />
          <ScopeCard targetId={targetId} />
          <PersonasCard targetId={targetId} rootDomain={target.root_domain} />
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

  if (!target.ownership_check_required) {
    return (
      <div className="card">
        <h2>
          Ownership &amp; authorization <span className="badge tone-muted">Not required</span>
        </h2>
        <p className="card-muted">
          Ownership verification is switched off on this deployment, so you can scan right away.
          Every request still stays on <span className="mono">{target.root_domain}</span> and its
          subdomains, within the scope rules below. Only scan sites the client has authorised you
          to test.
        </p>
      </div>
    );
  }

  return (
    <div className="card">
      <h2>
        Ownership &amp; authorization{" "}
        {target.is_scannable ? (
          <span className="badge tone-ok">Ready to scan</span>
        ) : (
          <span className="badge tone-pending">Incomplete</span>
        )}
      </h2>
      <p className="card-muted">
        Two steps before the first scan: prove you control the domain, then confirm testing is
        authorized.
      </p>

      {error && <div className="error-box" style={{ margin: "10px 0" }}>{error}</div>}

      {/* Step 1: ownership */}
      <h3 style={{ marginTop: 14 }}>
        1. Ownership{" "}
        {target.ownership_verified ? (
          <span className="badge tone-ok">Verified</span>
        ) : (
          <span className="badge tone-pending">Not verified</span>
        )}
      </h3>
      {!target.ownership_verified ? (
        <>
          <div className="inline-form" style={{ marginTop: 6 }}>
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
        <div className="hint">
          Verified
          {target.ownership_verification_method ? ` via ${target.ownership_verification_method}` : ""}.
        </div>
      )}

      {/* Step 2: authorization — always shown, so the second step is visible up front */}
      <h3 style={{ marginTop: 16 }}>
        2. Testing authorization{" "}
        {target.authorization_accepted ? (
          <span className="badge tone-ok">Accepted</span>
        ) : (
          <span className="badge tone-pending">Not accepted</span>
        )}
      </h3>
      {!target.authorization_accepted && (
        <div>
          <button
            className="btn-primary"
            disabled={busy || !target.ownership_verified}
            onClick={accept}
          >
            Accept testing authorization
          </button>
          <div className="hint" style={{ marginTop: 6 }}>
            {target.ownership_verified
              ? "Confirms you own, or are contractually authorized to test, this target."
              : "Available once ownership is verified (step 1)."}
          </div>
        </div>
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

  async function remove(rule: ScopeRule) {
    if (!window.confirm(`Delete scope rule "${rule.effect} ${rule.kind}: ${rule.pattern}"?`)) return;
    setFormErr(null);
    try {
      await api.deleteScopeRule(targetId, rule.id);
      refresh();
    } catch (e) {
      setFormErr(e instanceof ApiError ? e.detail : String(e));
    }
  }

  async function add(e?: React.FormEvent) {
    e?.preventDefault();
    if (!pattern.trim() || busy) return;
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
              <span className="grow mono" style={{ overflowWrap: "anywhere" }}>{r.kind}: {r.pattern}</span>
              <button className="btn-sm" type="button" onClick={() => remove(r)} aria-label="Delete rule">
                Delete
              </button>
            </div>
          ))}
        </div>
      )}

      <form className="inline-form" onSubmit={add}>
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
          <input
            value={pattern}
            placeholder={SCOPE_PLACEHOLDER[kind]}
            className="mono"
            onChange={(e) => setPattern(e.target.value)}
          />
        </div>
        <div style={{ maxWidth: 140 }}>
          <label>Effect</label>
          <select value={effect} onChange={(e) => setEffect(e.target.value)}>
            <option value="include">include</option>
            <option value="exclude">exclude</option>
          </select>
        </div>
        <button type="submit" disabled={busy || !pattern.trim()}>Add</button>
      </form>
      <div className="hint" style={{ marginTop: 6 }}>{SCOPE_HELP[kind]}</div>
    </div>
  );
}

const SCOPE_PLACEHOLDER: Record<string, string> = {
  host: "api.client.com or *.client.com",
  path_prefix: "/payments/",
  path_regex: "^/classes/\\d+/attendance",
  method: "DELETE",
};

const SCOPE_HELP: Record<string, string> = {
  host: "A host (or *.host for its subdomains). Include rules limit the scan to these hosts; exclude rules carve them out.",
  path_prefix: "A URL path that starts with /, e.g. /payments/ — exclude it to keep the scanner away from checkout or other risky areas.",
  path_regex: "A regular expression matched against the URL path (Python syntax). Checked when you save.",
  method: "An HTTP method such as DELETE or POST. Exclude it to stop the scanner sending that kind of request.",
};

function PersonasCard({ targetId, rootDomain }: { targetId: string; rootDomain: string }) {
  const { data: personas, error, refresh } = usePoll<Persona[]>(
    () => api.listPersonas(targetId),
    30000,
  );
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<string | null>(null);

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
            <div key={p.id}>
              <div className="list-item">
                <div className="grow">
                  <div className="title">
                    {p.label} <span className="hint">({p.role_name}, trust {p.trust_rank})</span>
                  </div>
                  <div className="sub">
                    {p.tenant_key ? `tenant ${p.tenant_key}` : "no tenant"}
                    {p.has_login_recipe ? " · logs in with a recipe" : " · no login — scans as anonymous"}
                  </div>
                  {!p.is_available && p.unavailable_reason && (
                    <div className="sub" style={{ color: "var(--bad, #f87171)" }}>
                      Last login failed: {p.unavailable_reason}
                    </div>
                  )}
                </div>
                {!p.has_login_recipe ? (
                  <span className="badge tone-muted">No login</span>
                ) : p.is_available ? (
                  <span className="badge tone-ok" title="Checked on the next scan">Login set</span>
                ) : (
                  <span className="badge tone-bad">Login failed</span>
                )}
                <button
                  className="btn-sm"
                  onClick={() => setEditing(editing === p.id ? null : p.id)}
                >
                  {editing === p.id ? "Close" : p.has_login_recipe ? "Edit login" : "Set up login"}
                </button>
              </div>
              {editing === p.id && (
                <EditLogin
                  targetId={targetId}
                  rootDomain={rootDomain}
                  persona={p}
                  onDone={() => {
                    setEditing(null);
                    refresh();
                  }}
                />
              )}
            </div>
          ))}
        </div>
      )}

      {open ? (
        <AddPersona
          targetId={targetId}
          rootDomain={rootDomain}
          onDone={() => { setOpen(false); refresh(); }}
          onCancel={() => setOpen(false)}
        />
      ) : (
        <button onClick={() => setOpen(true)}>+ Add persona</button>
      )}
    </div>
  );
}

function EditLogin({
  targetId,
  rootDomain,
  persona,
  onDone,
}: {
  targetId: string;
  rootDomain: string;
  persona: Persona;
  onDone: () => void;
}) {
  const [login, setLogin] = useState<LoginForm>(EMPTY_LOGIN);
  const [hasPassword, setHasPassword] = useState(false);
  const [loaded, setLoaded] = useState(!persona.has_login_recipe);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showErrors, setShowErrors] = useState(false);

  // QA #24: open with the saved recipe filled in (never the password: the
  // API only says whether one is stored).
  useEffect(() => {
    let cancelled = false;
    api
      .getPersonaLogin(targetId, persona.id)
      .then((res) => {
        if (cancelled) return;
        // Only replace the form when there is something saved to show: a
        // persona without a recipe is editable immediately, and its fetch
        // must not wipe what the user has already typed.
        if (res.login_recipe) setLogin(loginFormFromRecipe(res.login_recipe));
        setHasPassword(res.has_password);
      })
      .catch((e) => !cancelled && setError(e instanceof ApiError ? e.detail : String(e)))
      .finally(() => !cancelled && setLoaded(true));
    return () => {
      cancelled = true;
    };
  }, [targetId, persona.id]);

  async function save(e?: React.FormEvent) {
    e?.preventDefault();
    if (busy) return;
    setShowErrors(true);
    // Saving replaces the whole recipe. The password may be left blank when
    // one is already stored: the stored one is kept.
    const built = buildLogin(login, !hasPassword, rootDomain);
    if (!built.ok) {
      setError("Fix the highlighted fields.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const body: Record<string, unknown> = { login_recipe: built.recipe };
      if (built.password) body.credential = { kind: "password", secret: built.password };
      await api.updatePersonaLogin(targetId, persona.id, body);
      onDone();
    } catch (e) {
      setError(e instanceof ApiError ? e.detail : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form
      onSubmit={save}
      style={{ border: "1px solid var(--border)", borderRadius: 8, padding: 12, margin: "6px 0 10px" }}
    >
      {!loaded ? (
        <div className="hint">Loading saved login…</div>
      ) : (
        <>
          {hasPassword && (
            <div className="hint" style={{ marginBottom: 6 }}>
              Showing the saved login. The password is never shown: leave it blank to keep the current
              one.
            </div>
          )}
          {error && <div className="error-box" style={{ marginBottom: 8 }}>{error}</div>}
          <LoginRecipeFields
            value={login}
            onChange={setLogin}
            rootDomain={rootDomain}
            passwordRequired={!hasPassword}
            showErrors={showErrors}
            passwordHint={hasPassword ? "leave blank to keep current" : undefined}
          />
          <div className="row" style={{ marginTop: 12 }}>
            <button className="btn-primary" type="submit" disabled={busy}>
              {busy ? "Saving…" : "Save login"}
            </button>
          </div>
        </>
      )}
    </form>
  );
}

function AddPersona({
  targetId,
  rootDomain,
  onDone,
  onCancel,
}: {
  targetId: string;
  rootDomain: string;
  onDone: () => void;
  onCancel: () => void;
}) {
  const [label, setLabel] = useState("");
  const [role, setRole] = useState("");
  const [trust, setTrust] = useState(0);
  const [tenant, setTenant] = useState("");
  const [withLogin, setWithLogin] = useState(true);
  const [showErrors, setShowErrors] = useState(false);
  const [login, setLogin] = useState<LoginForm>(EMPTY_LOGIN);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e?: React.FormEvent) {
    e?.preventDefault();
    if (busy) return;
    if (!label.trim() || !role.trim()) {
      setError("Enter a label and a role name.");
      return;
    }
    setError(null);
    const body: Record<string, unknown> = {
      label: label.trim(),
      role_name: role.trim(),
      trust_rank: trust,
      tenant_key: tenant.trim() || null,
      expected_denied: [],
    };
    if (withLogin) {
      setShowErrors(true);
      const built = buildLogin(login, true, rootDomain);
      if (!built.ok) {
        setError("Fix the highlighted login fields.");
        return;
      }
      body.login_strategy = "form";
      body.login_recipe = built.recipe;
      body.credential = { kind: "password", secret: built.password };
    }
    setBusy(true);
    try {
      await api.createPersona(targetId, body);
      onDone();
    } catch (e) {
      setError(e instanceof ApiError ? e.detail : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form
      onSubmit={submit}
      style={{ borderTop: "1px solid var(--border)", marginTop: 12, paddingTop: 12 }}
    >
      {error && <div className="error-box" style={{ marginBottom: 8 }}>{error}</div>}
      <div className="row">
        <div>
          <label>Label *</label>
          <input value={label} required placeholder="Admin user" onChange={(e) => setLabel(e.target.value)} />
        </div>
        <div>
          <label>Role name *</label>
          <input value={role} required placeholder="admin" onChange={(e) => setRole(e.target.value)} />
        </div>
      </div>
      <div className="row">
        <div style={{ maxWidth: 140 }}>
          <label>Trust rank</label>
          <input
            type="number"
            min={0}
            max={1000}
            value={trust}
            onChange={(e) => setTrust(Math.max(0, Math.min(1000, Math.trunc(Number(e.target.value) || 0))))}
          />
        </div>
        <div>
          <label>Tenant key (optional)</label>
          <input value={tenant} placeholder="tenant-a" onChange={(e) => setTenant(e.target.value)} />
        </div>
      </div>
      <div className="hint" style={{ marginTop: 4 }}>
        <b>Trust rank</b> orders roles by privilege (0 = logged out, e.g. 10 member, 50 admin, max
        1000): a lower-ranked persona reaching a higher-ranked one&apos;s pages is a finding.{" "}
        <b>Tenant key</b> groups personas that belong to the same customer account: one tenant
        reaching another tenant&apos;s data is a finding.
      </div>
      <label style={{ display: "flex", gap: 8, alignItems: "center", marginTop: 14 }}>
        <input
          type="checkbox"
          checked={withLogin}
          onChange={(e) => setWithLogin(e.target.checked)}
          style={{ width: "auto" }}
        />
        Log in as this persona
      </label>
      {withLogin ? (
        <LoginRecipeFields
          value={login}
          onChange={setLogin}
          rootDomain={rootDomain}
          passwordRequired
          showErrors={showErrors}
        />
      ) : (
        <div className="hint">
          Without a login this persona browses anonymously, which is useful as the &quot;logged-out
          visitor&quot; to compare against. Authorization checks need at least two logged-in personas.
        </div>
      )}
      <div className="row" style={{ marginTop: 12 }}>
        <button className="btn-primary" type="submit" disabled={busy}>
          {busy ? "Saving…" : "Save persona"}
        </button>
        <button type="button" onClick={onCancel}>Cancel</button>
      </div>
    </form>
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
            Complete both ownership steps above first.
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
