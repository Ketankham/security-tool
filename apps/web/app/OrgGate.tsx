"use client";

import { useEffect, useState } from "react";
import { ApiError, api, getOrgId, setOrgId } from "@/lib/api";

// Auth today is a dev stand-in: the API trusts an X-Org-Id header
// (apps/api/.../deps.get_current_org). This gate stores a chosen org id in
// localStorage and lets the user either create a fresh org or paste an
// existing id. When Clerk lands, this screen becomes a real sign-in.
export function OrgGate({ children }: { children: React.ReactNode }) {
  const [ready, setReady] = useState(false);
  const [orgId, setOrg] = useState<string | null>(null);

  useEffect(() => {
    setOrg(getOrgId());
    setReady(true);
  }, []);

  if (!ready) return null;
  if (orgId) return <>{children}</>;
  return <OrgSetup onDone={(id) => setOrg(id)} />;
}

function OrgSetup({ onDone }: { onDone: (id: string) => void }) {
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [pasteId, setPasteId] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function pick(id: string) {
    setOrgId(id);
    window.dispatchEvent(new Event("sentinel:org"));
    onDone(id);
  }

  async function create() {
    setBusy(true);
    setError(null);
    try {
      const org = await api.createOrg(name.trim(), slug.trim());
      pick(org.id);
    } catch (e) {
      setError(e instanceof ApiError ? e.detail : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card" style={{ maxWidth: 560, margin: "48px auto" }}>
      <h2>Choose an organization</h2>
      <p className="card-muted">
        Auth is a development stand-in for now. Create an organization to get
        started, or paste an existing organization id.
      </p>

      {error && <div className="error-box" style={{ marginBottom: 12 }}>{error}</div>}

      <h3 style={{ marginTop: 18 }}>Create new</h3>
      <div className="row">
        <div style={{ flex: 2 }}>
          <label>Name</label>
          <input
            value={name}
            placeholder="Acme Inc."
            onChange={(e) => {
              setName(e.target.value);
              if (!slug) setSlug(e.target.value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, ""));
            }}
          />
        </div>
        <div>
          <label>Slug</label>
          <input value={slug} placeholder="acme" onChange={(e) => setSlug(e.target.value)} />
        </div>
      </div>
      <div style={{ marginTop: 12 }}>
        <button className="btn-primary" disabled={busy || !name.trim() || !slug.trim()} onClick={create}>
          {busy ? "Creating…" : "Create organization"}
        </button>
      </div>

      <h3 style={{ marginTop: 24 }}>Use existing id</h3>
      <div className="inline-form">
        <div style={{ flex: 1 }}>
          <input
            value={pasteId}
            placeholder="00000000-0000-0000-0000-000000000000"
            className="mono"
            onChange={(e) => setPasteId(e.target.value)}
          />
        </div>
        <button disabled={!pasteId.trim()} onClick={() => pick(pasteId.trim())}>
          Use this org
        </button>
      </div>
    </div>
  );
}
