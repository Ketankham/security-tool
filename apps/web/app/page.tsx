"use client";

import Link from "next/link";
import { useState } from "react";
import { OrgGate } from "./OrgGate";
import { ApiError, api } from "@/lib/api";
import { usePoll } from "@/lib/usePoll";
import type { Target } from "@/lib/types";

export default function Home() {
  return (
    <OrgGate>
      <Dashboard />
    </OrgGate>
  );
}

function Dashboard() {
  const { data: targets, error, loading, refresh } = usePoll<Target[]>(
    () => api.listTargets(),
    15000,
  );

  return (
    <>
      <h1 style={{ marginTop: 24 }}>Targets</h1>
      <p className="card-muted">
        Each target is a web application you are authorized to test. Add one,
        verify ownership, define personas, then run scans.
      </p>

      {error && <div className="error-box">{error}</div>}

      <AddTarget onAdded={refresh} />

      {loading && !targets && <div className="notice">Loading targets…</div>}

      {targets && targets.length === 0 && (
        <div className="empty">No targets yet. Add your first application above.</div>
      )}

      {targets && targets.length > 0 && (
        <div className="list">
          {targets.map((t) => (
            <Link key={t.id} href={`/targets/${t.id}`} className="list-item" style={{ color: "inherit" }}>
              <div className="grow">
                <div className="title">{t.display_name}</div>
                <div className="sub mono">{t.root_domain}</div>
              </div>
              {t.is_scannable ? (
                <span className="badge tone-ok">Scannable</span>
              ) : t.ownership_verified ? (
                <span className="badge tone-running">Needs authorization</span>
              ) : (
                <span className="badge tone-pending">Unverified</span>
              )}
            </Link>
          ))}
        </div>
      )}
    </>
  );
}

function AddTarget({ onAdded }: { onAdded: () => void }) {
  const [open, setOpen] = useState(false);
  const [domain, setDomain] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [isProd, setIsProd] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      await api.createTarget({
        root_domain: domain.trim(),
        display_name: displayName.trim() || domain.trim(),
        is_production: isProd,
      });
      setDomain("");
      setDisplayName("");
      setOpen(false);
      onAdded();
    } catch (e) {
      setError(e instanceof ApiError ? e.detail : String(e));
    } finally {
      setBusy(false);
    }
  }

  if (!open) {
    return (
      <div style={{ margin: "14px 0" }}>
        <button className="btn-primary" onClick={() => setOpen(true)}>
          + Add target
        </button>
      </div>
    );
  }

  return (
    <div className="card">
      <h2>Add target</h2>
      {error && <div className="error-box" style={{ marginBottom: 10 }}>{error}</div>}
      <div className="row">
        <div>
          <label>Root domain</label>
          <input value={domain} placeholder="app.example.com" onChange={(e) => setDomain(e.target.value)} />
        </div>
        <div>
          <label>Display name</label>
          <input value={displayName} placeholder="Example App" onChange={(e) => setDisplayName(e.target.value)} />
        </div>
      </div>
      <label style={{ marginTop: 12 }}>
        <input
          type="checkbox"
          checked={isProd}
          onChange={(e) => setIsProd(e.target.checked)}
          style={{ width: "auto", marginRight: 8 }}
        />
        This is a production environment
      </label>
      <div className="row" style={{ marginTop: 14 }}>
        <button className="btn-primary" disabled={busy || !domain.trim()} onClick={submit}>
          {busy ? "Adding…" : "Add"}
        </button>
        <button onClick={() => setOpen(false)}>Cancel</button>
      </div>
    </div>
  );
}
