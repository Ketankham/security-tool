"use client";

import { useEffect, useState } from "react";
import { ApiError, api, clearOrgId, getOrgId, setOrgId } from "@/lib/api";

// Auth today is a dev stand-in: the API trusts an X-Org-Id header
// (apps/api/.../deps.get_current_org). This gate stores a chosen org id in
// localStorage and lets the user either create a fresh org or paste an
// existing id. When Clerk lands, this screen becomes a real sign-in.
export function OrgGate({ children }: { children: React.ReactNode }) {
  const [ready, setReady] = useState(false);
  const [orgId, setOrg] = useState<string | null>(null);

  useEffect(() => {
    const sync = () => setOrg(getOrgId());
    sync();
    setReady(true);
    // Re-read whenever the org changes elsewhere: "Switch" in the top bar,
    // another tab, or a page restored from the back/forward cache after the
    // org was cleared (QA #15: the page used to keep rendering with no org
    // and no way to pick one).
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
  return <OrgSetup onDone={(id) => setOrg(id)} />;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

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

const SLUG_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

function OrgSetup({ onDone }: { onDone: (id: string) => void }) {
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [slugTouched, setSlugTouched] = useState(false);
  const [pasteId, setPasteId] = useState("");
  const [busy, setBusy] = useState(false);
  // Errors belong to the form they came from and clear as soon as that form
  // is edited, so an emptied chooser never shows a stale message (QA #27).
  const [createError, setCreateError] = useState<string | null>(null);
  const [pasteError, setPasteError] = useState<string | null>(null);

  function pick(id: string) {
    setOrgId(id);
    window.dispatchEvent(new Event("sentinel:org"));
    onDone(id);
  }

  // QA #25: invalid slugs are reported (not silently rewritten) and keep
  // Create disabled until fixed.
  const slugProblem = !slug
    ? "Enter a slug."
    : /[A-Z]/.test(slug)
      ? "Use lower-case letters only."
      : /\s/.test(slug)
        ? "No spaces: join words with hyphens, e.g. acme-inc."
        : slug.length < 2
          ? "The slug needs at least 2 characters."
          : !SLUG_RE.test(slug)
            ? "Use letters and digits, with single hyphens between words."
            : null;
  const createProblem = !name.trim() ? "Enter a name." : slugProblem;

  async function create(e: React.FormEvent) {
    e.preventDefault();
    if (createProblem || busy) return;
    setBusy(true);
    setCreateError(null);
    try {
      const org = await api.createOrg(name.trim(), slug);
      pick(org.id);
    } catch (err) {
      setCreateError(err instanceof ApiError ? err.detail : String(err));
    } finally {
      setBusy(false);
    }
  }

  // QA #13: check the id's format, then that the org exists, before
  // switching to it — instead of storing any text and failing later.
  async function useExisting(e: React.FormEvent) {
    e.preventDefault();
    const id = pasteId.trim();
    if (!UUID_RE.test(id)) {
      setPasteError("That isn't an organization id. It looks like 6fa9094d-1c2e-4b8a-9f0e-0123456789ab.");
      return;
    }
    setBusy(true);
    setPasteError(null);
    setOrgId(id);
    try {
      await api.me();
      pick(id);
    } catch (err) {
      clearOrgId();
      setPasteError(
        err instanceof ApiError && err.status === 404
          ? "No organization has that id."
          : err instanceof ApiError
            ? err.detail
            : String(err),
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card" style={{ maxWidth: 560, margin: "48px auto" }}>
      <h2>Choose an organization</h2>
      <p className="card-muted">
        An organization holds your targets, personas and scans. There are no user accounts yet: the
        organization id works like a shared access key, so anyone with it can open that
        organization&apos;s data. Keep it private.
      </p>

      <h3 style={{ marginTop: 18 }}>Create new</h3>
      <form onSubmit={create}>
        {createError && <div className="error-box" style={{ marginBottom: 8 }}>{createError}</div>}
        <div className="row">
          <div style={{ flex: 2 }}>
            <label>Name *</label>
            <input
              value={name}
              required
              maxLength={120}
              placeholder="Acme Inc."
              onChange={(e) => {
                setCreateError(null);
                setName(e.target.value);
                if (!slugTouched) setSlug(slugify(e.target.value));
              }}
            />
          </div>
          <div>
            <label>Slug *</label>
            <input
              value={slug}
              required
              maxLength={63}
              placeholder="acme"
              className="mono"
              aria-invalid={!!(slug && slugProblem)}
              onChange={(e) => {
                setCreateError(null);
                setSlugTouched(true);
                setSlug(e.target.value);
              }}
            />
          </div>
        </div>
        <div className="hint" style={{ marginTop: 4 }}>
          The slug is a short, unique, URL-friendly name, e.g. <span className="mono">acme-inc</span>.
        </div>
        <div style={{ marginTop: 12 }}>
          <button className="btn-primary" type="submit" disabled={busy || !!createProblem}>
            {busy ? "Creating…" : "Create organization"}
          </button>
          {createProblem && (
            <span className={name || slug ? "field-error" : "hint"} style={{ marginLeft: 10, display: "inline" }}>
              {createProblem}
            </span>
          )}
        </div>
      </form>

      <h3 style={{ marginTop: 24 }}>Use existing id</h3>
      <form className="inline-form" onSubmit={useExisting}>
        <div style={{ flex: 1 }}>
          <input
            value={pasteId}
            placeholder="00000000-0000-0000-0000-000000000000"
            className="mono"
            onChange={(e) => {
              setPasteError(null);
              setPasteId(e.target.value);
            }}
          />
        </div>
        <button type="submit" disabled={busy || !pasteId.trim()}>
          Use this org
        </button>
      </form>
      {pasteError && pasteId.trim() && <div className="field-error">{pasteError}</div>}
      <div className="hint" style={{ marginTop: 4 }}>
        Find it with &quot;Copy id&quot; in the top bar while that organization is selected.
      </div>
    </div>
  );
}
