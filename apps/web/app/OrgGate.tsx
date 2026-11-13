"use client";

import { useEffect, useState } from "react";
import { ApiError, api, clearOrgId, getOrgId, setOrgId } from "@/lib/api";
import type { OrganizationSummary } from "@/lib/types";

// There are no user accounts: the API scopes data by an organization id
// (X-Org-Id header) kept in localStorage. Picking one is a click in the list
// of all organizations; with exactly one, it opens straight away.
export function OrgGate({ children }: { children: React.ReactNode }) {
  const [ready, setReady] = useState(false);
  const [orgId, setOrg] = useState<string | null>(null);

  useEffect(() => {
    const sync = () => setOrg(getOrgId());
    sync();
    setReady(true);
    // A saved organization that no longer exists (e.g. the database was
    // reset) would make every page fail: forget it and show the list.
    if (getOrgId()) {
      api.me().catch((e) => {
        if (e instanceof ApiError && e.status === 404) {
          clearOrgId();
          window.dispatchEvent(new Event("sentinel:org")); // top bar too
          sync();
        }
      });
    }
    // Re-read whenever the org changes elsewhere: "Switch" in the top bar,
    // another tab, or a page restored from the back/forward cache (QA #15).
    window.addEventListener("storage", sync);
    window.addEventListener("sentinel:org", sync);
    window.addEventListener("pageshow", sync);
    return () => {
      window.removeEventListener("storage", sync);
      window.removeEventListener("sentinel:org", sync);
      window.removeEventListener("pageshow", sync);
    };
  }, []);

  // A shell straight away instead of a blank first paint (QA #6).
  if (!ready) return <div className="notice" style={{ marginTop: 24 }}>Loading…</div>;
  if (orgId) return <>{children}</>;
  return <OrgPicker onDone={(id) => setOrg(id)} />;
}

export function pickOrg(id: string) {
  setOrgId(id);
  window.dispatchEvent(new Event("sentinel:org"));
}

// "Café Ünïon & Co!" -> "cafe-union-co". Mirrors the API's slug rule:
// lower-case words joined by single hyphens, 2–63 characters.
export function slugify(name: string): string {
  return name
    .normalize("NFKD")
    .replace(/[̀-ͯ]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 63)
    .replace(/-+$/g, "");
}

function OrgPicker({ onDone }: { onDone: (id: string) => void }) {
  const [orgs, setOrgs] = useState<OrganizationSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  function choose(id: string) {
    pickOrg(id);
    onDone(id);
  }

  useEffect(() => {
    api
      .listOrgs()
      .then((list) => {
        // Only one organization: nothing to choose, open it (unless the
        // user came here with "Switch organization").
        const switching = new URLSearchParams(window.location.search).has("pick");
        if (list.length === 1 && !switching) choose(list[0].id);
        else setOrgs(list);
      })
      .catch((e) => setError(e instanceof ApiError ? e.detail : String(e)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="card" style={{ maxWidth: 640, margin: "48px auto" }}>
      <h2>Organizations</h2>
      {error && <div className="error-box">{error}</div>}
      {!orgs && !error && <div className="hint">Loading…</div>}
      {orgs && orgs.length === 0 && (
        <p className="card-muted">No organizations yet. Create the first one below.</p>
      )}
      {orgs && orgs.length > 0 && (
        <div className="list" style={{ margin: "10px 0" }}>
          {orgs.map((o) => (
            <button
              key={o.id}
              type="button"
              className="list-item"
              onClick={() => choose(o.id)}
              style={{ width: "100%", textAlign: "left", cursor: "pointer" }}
            >
              <div className="grow">
                <div className="title">{o.name}</div>
                <div className="sub">
                  {o.target_count === 0
                    ? "no targets yet"
                    : `${o.target_count} target${o.target_count === 1 ? "" : "s"}: ${o.target_domains.join(", ")}${o.target_count > o.target_domains.length ? ", …" : ""}`}
                </div>
              </div>
              <span className="hint">Open →</span>
            </button>
          ))}
        </div>
      )}

      {creating ? (
        <CreateOrg onCreated={choose} onCancel={() => setCreating(false)} />
      ) : (
        <button type="button" style={{ marginTop: 8 }} onClick={() => setCreating(true)}>
          + New organization
        </button>
      )}
    </div>
  );
}

function CreateOrg({ onCreated, onCancel }: { onCreated: (id: string) => void; onCancel: () => void }) {
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // The slug is derived from the name; a short random suffix keeps it unique
  // without asking the user to invent one.
  const base = slugify(name);
  const problem = !name.trim() ? "Enter a name." : base.length < 2 ? "Use at least 2 letters or digits." : null;

  async function create(e: React.FormEvent) {
    e.preventDefault();
    if (problem || busy) return;
    setBusy(true);
    setError(null);
    try {
      let org;
      try {
        org = await api.createOrg(name.trim(), base);
      } catch (err) {
        if (!(err instanceof ApiError && err.status === 409)) throw err;
        const suffix = Math.random().toString(36).slice(2, 6);
        org = await api.createOrg(name.trim(), `${base.slice(0, 58)}-${suffix}`);
      }
      onCreated(org.id);
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : String(err));
      setBusy(false);
    }
  }

  return (
    <form onSubmit={create} style={{ borderTop: "1px solid var(--border)", marginTop: 12, paddingTop: 12 }}>
      {error && <div className="error-box" style={{ marginBottom: 8 }}>{error}</div>}
      <label>Name *</label>
      <input
        value={name}
        maxLength={120}
        placeholder="Abhyaasika"
        autoFocus
        onChange={(e) => {
          setError(null);
          setName(e.target.value);
        }}
      />
      <div className="row" style={{ marginTop: 10 }}>
        <button className="btn-primary" type="submit" disabled={busy || !!problem}>
          {busy ? "Creating…" : "Create"}
        </button>
        <button type="button" onClick={onCancel}>Cancel</button>
      </div>
    </form>
  );
}
