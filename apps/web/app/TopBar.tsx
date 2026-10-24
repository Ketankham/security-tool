"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { clearOrgId, getOrgId } from "@/lib/api";

export function TopBar() {
  const [orgId, setOrg] = useState<string | null>(null);

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

  return (
    <header className="topbar">
      <div className="topbar-inner">
        <Link href="/" className="brand">
          Sentinel<span>.</span>
        </Link>
        <div className="spacer" />
        {orgId && (
          <>
            <span className="org-chip" title="Active organization (dev auth stand-in)">
              org {orgId.slice(0, 8)}…
            </span>
            <button
              className="btn-sm"
              onClick={() => {
                clearOrgId();
                window.dispatchEvent(new Event("sentinel:org"));
                window.location.href = "/";
              }}
            >
              Switch
            </button>
          </>
        )}
      </div>
    </header>
  );
}
