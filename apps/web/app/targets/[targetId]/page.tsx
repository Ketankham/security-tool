"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { use, useEffect, useState } from "react";
import { OrgGate } from "../../OrgGate";
import { ApiError, api } from "@/lib/api";
import { usePoll } from "@/lib/usePoll";
import { scanStatus } from "@/lib/scan";
import type {
  LoginTestResult,
  ScanDepth,
  ScanSpeed,
  OwnershipChallenge,
  OwnershipMethod,
  Persona,
  Scan,
  ScopeRule,
  Target,
} from "@/lib/types";
import {
  EMPTY_LOGIN,
  LoginRecipeFields,
  blockingLoginProblem,
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
          <TargetHeader target={target} onChange={refresh} />

          {/* Hidden when this deployment doesn't require ownership checks. */}
          {target.ownership_check_required && (
            <OwnershipCard target={target} onChange={refresh} />
          )}
          <ScopeCard targetId={targetId} />
          <PersonasCard targetId={targetId} rootDomain={target.root_domain} />
          <ScansCard target={target} />
        </>
      )}
    </>
  );
}

// Edit a target's name / domain, or delete it (QA "can't edit or delete").
// Changing the domain is the fix for QA #37: abhyaasika.com -> www.abhyaasika.com.
function TargetHeader({ target, onChange }: { target: Target; onChange: () => void }) {
  const router = useRouter();
  const [editing, setEditing] = useState(false);
  const [name, setName] = useState(target.display_name);
  const [domain, setDomain] = useState(target.root_domain);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function save(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.updateTarget(target.id, { display_name: name.trim(), root_domain: domain.trim() });
      setEditing(false);
      onChange();
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : String(err));
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    const typed = window.prompt(
      `Delete ${target.root_domain} with its personas (and their stored logins), scope rules and all scans? This can't be undone.\n\nType the domain to confirm:`,
    );
    if (typed === null) return;
    if (typed.trim().toLowerCase() !== target.root_domain) {
      setError("The domain didn't match, so nothing was deleted.");
      return;
    }
    try {
      await api.deleteTarget(target.id);
      router.push("/");
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : String(err));
    }
  }

  if (!editing) {
    return (
      <div style={{ display: "flex", alignItems: "flex-start", gap: 10 }}>
        <div style={{ flex: 1 }}>
          <h1>{target.display_name}</h1>
          <p className="card-muted mono">{target.root_domain}</p>
          {error && <div className="error-box">{error}</div>}
        </div>
        <button
          className="btn-sm"
          style={{ marginTop: 18 }}
          onClick={() => {
            setName(target.display_name);
            setDomain(target.root_domain);
            setEditing(true);
          }}
        >
          Edit
        </button>
        <button className="btn-sm" style={{ marginTop: 18 }} onClick={remove}>
          Delete
        </button>
      </div>
    );
  }
  return (
    <form className="card" onSubmit={save}>
      {error && <div className="error-box" style={{ marginBottom: 8 }}>{error}</div>}
      <div className="row">
        <div>
          <label>Name</label>
          <input value={name} maxLength={200} onChange={(e) => setName(e.target.value)} />
        </div>
        <div>
          <label>Domain</label>
          <input className="mono" value={domain} onChange={(e) => setDomain(e.target.value)} />
        </div>
      </div>
      <div className="hint" style={{ marginTop: 4 }}>
        Use the host the app actually runs on, e.g. <span className="mono">www.abhyaasika.com</span>{" "}
        if <span className="mono">abhyaasika.com</span> just redirects there. Subdomains of it are in
        scope too.
      </div>
      <div className="row" style={{ marginTop: 10 }}>
        <button className="btn-primary" type="submit" disabled={busy || !name.trim() || !domain.trim()}>
          {busy ? "Saving…" : "Save"}
        </button>
        <button
          type="button"
          onClick={() => {
            setEditing(false);
            setName(target.display_name);
            setDomain(target.root_domain);
            setError(null);
          }}
        >
          Cancel
        </button>
      </div>
    </form>
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
  const [testing, setTesting] = useState<string | null>(null);
  const [details, setDetails] = useState<string | null>(null);
  const [rowError, setRowError] = useState<string | null>(null);

  async function removePersona(p: Persona) {
    if (!window.confirm(`Delete persona "${p.label}" and its stored login? Old scans are kept.`)) return;
    try {
      await api.deletePersona(targetId, p.id);
      setRowError(null);
      refresh();
    } catch (e) {
      setRowError(e instanceof ApiError ? e.detail : String(e));
    }
  }

  return (
    <div className="card">
      <h2>Personas</h2>
      <p className="card-muted">
        Each persona is a login with a role and (optionally) a tenant. The
        authorization engine replays every persona&apos;s requests as every
        other identity to find who can reach what they shouldn&apos;t.
      </p>
      {error && <div className="error-box">{error}</div>}
      {rowError && <div className="error-box">{rowError}</div>}

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
                    {p.has_login_recipe
                      ? ` · logs in with ${STRATEGY_TEXT[p.login_strategy ?? "form"] ?? "a recipe"}`
                      : " · no login — scans as anonymous"}
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
                  <span className="badge tone-ok" title="Use Test login to check it now">Login set</span>
                ) : (
                  <span className="badge tone-bad">Login failed</span>
                )}
                {p.has_login_recipe && (
                  <button
                    className="btn-sm"
                    onClick={() => setTesting(testing === p.id ? null : p.id)}
                  >
                    {testing === p.id ? "Hide test" : "Test login"}
                  </button>
                )}
                <button
                  className="btn-sm"
                  onClick={() => setEditing(editing === p.id ? null : p.id)}
                >
                  {editing === p.id ? "Close" : p.has_login_recipe ? "Edit login" : "Set up login"}
                </button>
                <button
                  className="btn-sm"
                  onClick={() => setDetails(details === p.id ? null : p.id)}
                >
                  {details === p.id ? "Close" : "Details"}
                </button>
                <button className="btn-sm" onClick={() => removePersona(p)}>
                  Delete
                </button>
              </div>
              {details === p.id && (
                <PersonaDetails
                  targetId={targetId}
                  persona={p}
                  onDone={() => {
                    setDetails(null);
                    refresh();
                  }}
                />
              )}
              {testing === p.id && (
                <LoginTest targetId={targetId} persona={p} onFinished={refresh} />
              )}
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

function PersonaDetails({
  targetId,
  persona,
  onDone,
}: {
  targetId: string;
  persona: Persona;
  onDone: () => void;
}) {
  const [label, setLabel] = useState(persona.label);
  const [role, setRole] = useState(persona.role_name);
  const [trust, setTrust] = useState(persona.trust_rank);
  const [tenant, setTenant] = useState(persona.tenant_key ?? "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function save(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.updatePersonaLogin(targetId, persona.id, {
        label: label.trim(),
        role_name: role.trim(),
        trust_rank: trust,
        tenant_key: tenant.trim() || null,
      });
      onDone();
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form
      onSubmit={save}
      style={{ border: "1px solid var(--border)", borderRadius: 8, padding: 12, margin: "6px 0 10px" }}
    >
      {error && <div className="error-box" style={{ marginBottom: 8 }}>{error}</div>}
      <div className="row">
        <div>
          <label>Label</label>
          <input value={label} maxLength={200} onChange={(e) => setLabel(e.target.value)} />
        </div>
        <div>
          <label>Role name</label>
          <input value={role} maxLength={100} onChange={(e) => setRole(e.target.value)} />
        </div>
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
          <label>Tenant key</label>
          <input value={tenant} maxLength={200} onChange={(e) => setTenant(e.target.value)} />
        </div>
      </div>
      <div className="row" style={{ marginTop: 10 }}>
        <button className="btn-primary" type="submit" disabled={busy || !label.trim() || !role.trim()}>
          {busy ? "Saving…" : "Save details"}
        </button>
      </div>
    </form>
  );
}

const STRATEGY_TEXT: Record<string, string> = {
  form: "a login form",
  manual_session: "a pasted cookie",
  api_token: "a pasted header",
};

// v1 #1: replay the saved login once, in the worker, and show what happened:
// pass/fail, the reason, where the browser ended up, and a screenshot of it.
const TEST_TIMEOUT_MS = 150_000;

function LoginTest({
  targetId,
  persona,
  onFinished,
}: {
  targetId: string;
  persona: Persona;
  onFinished: () => void;
}) {
  const [result, setResult] = useState<LoginTestResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const [elapsed, setElapsed] = useState(0);
  const [run, setRun] = useState(0); // bump to start another test

  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const started = Date.now();
    setResult(null);
    setError(null);
    setRunning(true);
    setElapsed(0);

    async function poll(testId: string) {
      if (cancelled) return;
      try {
        const r = await api.getLoginTest(targetId, persona.id, testId);
        if (cancelled) return;
        if (r.status === "done") {
          setResult(r);
          setRunning(false);
          onFinished(); // the persona's Available/Failed status changed
          return;
        }
      } catch (e) {
        // A blip (e.g. a deploy restarting the API): keep polling until the deadline.
        if (e instanceof ApiError && e.status === 404) {
          setError(e.detail);
          setRunning(false);
          return;
        }
      }
      const spent = Date.now() - started;
      setElapsed(Math.round(spent / 1000));
      if (spent > TEST_TIMEOUT_MS) {
        setError(
          "No answer from the worker after 2½ minutes. Check that the worker containers are running, then try again.",
        );
        setRunning(false);
        return;
      }
      timer = setTimeout(() => poll(testId), 2000);
    }

    api
      .startLoginTest(targetId, persona.id)
      .then(({ test_id }) => poll(test_id))
      .catch((e) => {
        if (cancelled) return;
        setError(e instanceof ApiError ? e.detail : String(e));
        setRunning(false);
      });
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
    // onFinished is a stable refresh callback; re-running is driven by `run`.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [targetId, persona.id, run]);

  return (
    <div
      aria-live="polite"
      style={{ border: "1px solid var(--border)", borderRadius: 8, padding: 12, margin: "6px 0 10px" }}
    >
      {running && (
        <div className="hint">
          Logging in as {persona.label} in a real browser… {elapsed > 0 ? `${elapsed}s` : ""}
        </div>
      )}
      {error && <div className="error-box">{error}</div>}
      {result && (
        <>
          <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
            <span className={`badge tone-${result.success ? "ok" : "bad"}`}>
              {result.success ? "Login works" : "Login failed"}
            </span>
            {result.duration_s !== null && <span className="hint">took {result.duration_s}s</span>}
          </div>
          {!result.success && result.error && (
            <div className="field-error" style={{ marginTop: 6 }}>{result.error}</div>
          )}
          {result.final_url && (
            <div className="hint" style={{ marginTop: 6, wordBreak: "break-all" }}>
              Ended on <span className="mono">{result.final_url}</span>
            </div>
          )}
          {result.screenshot_jpeg_b64 && (
            // eslint-disable-next-line @next/next/no-img-element
            <img
              src={`data:image/jpeg;base64,${result.screenshot_jpeg_b64}`}
              alt={`What the browser showed at the end of ${persona.label}'s login`}
              style={{
                display: "block",
                marginTop: 8,
                maxWidth: "100%",
                border: "1px solid var(--border)",
                borderRadius: 6,
              }}
            />
          )}
        </>
      )}
      {!running && (
        <button className="btn-sm" style={{ marginTop: 8 }} onClick={() => setRun((n) => n + 1)}>
          Test again
        </button>
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
              Showing the saved login. The password, cookie or header value is never shown: leave it
              blank to keep the current one.
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
            <button
              className="btn-primary"
              type="submit"
              disabled={busy || !!blockingLoginProblem(login, rootDomain)}
              title={blockingLoginProblem(login, rootDomain) ?? undefined}
            >
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
        <button
          className="btn-primary"
          type="submit"
          disabled={busy || (withLogin && !!blockingLoginProblem(login, rootDomain))}
          title={(withLogin && blockingLoginProblem(login, rootDomain)) || undefined}
        >
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
  const [confirming, setConfirming] = useState(false);
  const [speed, setSpeed] = useState<ScanSpeed>("normal");
  const [depth, setDepth] = useState<ScanDepth>("standard");
  const { data: personas } = usePoll<Persona[]>(() => api.listPersonas(target.id), 30000);
  const { data: rules } = usePoll<ScopeRule[]>(() => api.listScopeRules(target.id), 30000);

  async function run() {
    setBusy(true);
    setStartErr(null);
    try {
      const scan = await api.createScan(target.id, { speed, depth });
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
        {!confirming ? (
          <button
            className="btn-primary"
            disabled={busy || !target.is_scannable}
            onClick={() => setConfirming(true)}
          >
            Run scan…
          </button>
        ) : (
          <RunScanPanel
            target={target}
            personas={personas ?? []}
            rules={rules ?? []}
            speed={speed}
            depth={depth}
            setSpeed={setSpeed}
            setDepth={setDepth}
            busy={busy}
            onStart={run}
            onCancel={() => setConfirming(false)}
          />
        )}
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
            .sort((a, b) => b.created_at.localeCompare(a.created_at))
            .map((s) => (
              <Link key={s.id} href={`/scans/${s.id}`} className="list-item" style={{ color: "inherit" }}>
                <div className="grow">
                  <div className="title mono">{s.id.slice(0, 8)}</div>
                  <div className="sub">
                    {s.triggered_by} · {new Date(s.started_at ?? s.created_at).toLocaleString()}
                  </div>
                  {s.fail_reason && (
                    <div className="sub" style={{ color: "var(--bad)" }}>{s.fail_reason}</div>
                  )}
                </div>
                <ScanStateBadge scan={s} />
              </Link>
            ))}
        </div>
      )}
    </div>
  );
}

const SPEEDS: { value: ScanSpeed; label: string; hint: string }[] = [
  { value: "gentle", label: "Gentle", hint: "2 requests/second — small or fragile sites" },
  { value: "normal", label: "Normal", hint: "5 requests/second" },
  { value: "fast", label: "Fast", hint: "10 requests/second — sturdy sites only" },
];
const DEPTHS: { value: ScanDepth; label: string; pages: number }[] = [
  { value: "quick", label: "Quick", pages: 30 },
  { value: "standard", label: "Standard", pages: 100 },
  { value: "deep", label: "Deep", pages: 300 },
];

// Run scan asks before starting: how hard to hit the site, how far to go,
// and a one-line summary of what will happen.
function RunScanPanel(props: {
  target: Target;
  personas: Persona[];
  rules: ScopeRule[];
  speed: ScanSpeed;
  depth: ScanDepth;
  setSpeed: (s: ScanSpeed) => void;
  setDepth: (d: ScanDepth) => void;
  busy: boolean;
  onStart: () => void;
  onCancel: () => void;
}) {
  const { target, personas, rules, speed, depth } = props;
  const logins = personas.filter((p) => p.has_login_recipe);
  const failing = logins.filter((p) => !p.is_available);
  const excluded = rules.filter((r) => r.effect === "exclude");
  const pages = DEPTHS.find((d) => d.value === depth)!.pages;
  return (
    <div style={{ border: "1px solid var(--border)", borderRadius: 8, padding: 12 }}>
      <div className="row">
        <div>
          <label>Speed</label>
          <select value={speed} onChange={(e) => props.setSpeed(e.target.value as ScanSpeed)} aria-label="Speed">
            {SPEEDS.map((s) => (
              <option key={s.value} value={s.value}>
                {s.label} — {s.hint}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label>Depth</label>
          <select value={depth} onChange={(e) => props.setDepth(e.target.value as ScanDepth)} aria-label="Depth">
            {DEPTHS.map((d) => (
              <option key={d.value} value={d.value}>
                {d.label} — up to {d.pages} pages per login
              </option>
            ))}
          </select>
        </div>
      </div>
      <p className="hint" style={{ marginTop: 8 }}>
        Crawls <span className="mono">{target.root_domain}</span> and its subdomains as a logged-out
        visitor{logins.length ? ` and as ${logins.map((p) => p.label).join(", ")}` : ""}, up to {pages}{" "}
        pages each, at most {SPEEDS.find((s) => s.value === speed)!.hint.split(" —")[0]}.
        {excluded.length > 0 && <> Skips {excluded.map((r) => r.pattern).join(", ")}.</>}
      </p>
      {failing.length > 0 && (
        <div className="notice" style={{ marginBottom: 8 }}>
          Last login failed for {failing.map((p) => p.label).join(", ")}: those roles won&apos;t be tested.
          Use Test login on the persona first.
        </div>
      )}
      <div className="row">
        <button className="btn-primary" disabled={props.busy} onClick={props.onStart}>
          {props.busy ? "Starting…" : "Start scan"}
        </button>
        <button type="button" onClick={props.onCancel}>Cancel</button>
      </div>
    </div>
  );
}

function ScanStateBadge({ scan }: { scan: Scan }) {
  const { label, tone } = scanStatus(scan);
  return <span className={`badge tone-${tone}`}>{label}</span>;
}
