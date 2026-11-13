"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { BASE_PATH, api, clearOrgId, getOrgId } from "@/lib/api";

export function TopBar() {
  const [orgId, setOrg] = useState<string | null>(null);
  const [orgName, setOrgName] = useState<string | null>(null);

  useEffect(() => {
    setOrg(getOrgId());
    const onStorage = () => setOrg(getOrgId());
    window.addEventListener("storage", onStorage);
    // Custom event so same-tab org changes refresh the chip too.
    window.addEventListener("sentinel:org", onStorage);
    return () => {
      window.removeEventListener("storage", onStorage);
      window.removeEventListener("sentinel:org", onStorage);
    };
  }, []);

  useEffect(() => {
    setOrgName(null);
    if (!orgId) return;
    api
      .me()
      .then((o) => setOrgName(o.name))
      .catch(() => setOrgName(null));
  }, [orgId]);

  return (
    <header className="topbar">
      <div className="topbar-inner">
        <Link href="/" className="brand">
          Sentinel<span>.</span>
        </Link>
        <div className="spacer" />
        {orgId && (
          <>
            <span className="org-chip" title={`Organization id: ${orgId}`}>
              {orgName ?? `org ${orgId.slice(0, 8)}…`}
            </span>
            <button
              className="btn-sm"
              onClick={() => {
                clearOrgId();
                window.dispatchEvent(new Event("sentinel:org"));
                // ?pick: show the list even when there's only one organization.
                window.location.href = `${BASE_PATH}/?pick=1`;
              }}
            >
              Switch organization
            </button>
          </>
        )}
      </div>
    </header>
  );
}
