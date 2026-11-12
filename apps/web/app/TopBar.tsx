"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { BASE_PATH, clearOrgId, getOrgId } from "@/lib/api";

export function TopBar() {
  const [orgId, setOrg] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

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
            <span className="org-chip mono" title={`Organization id: ${orgId}`}>
              org {orgId.slice(0, 8)}…
            </span>
            <button
              className="btn-sm"
              onClick={async () => {
                try {
                  await navigator.clipboard.writeText(orgId);
                  setCopied(true);
                  setTimeout(() => setCopied(false), 1500);
                } catch {
                  // Clipboard blocked (http, permissions): show it to copy by hand.
                  window.prompt("Organization id", orgId);
                }
              }}
            >
              {copied ? "Copied" : "Copy id"}
            </button>
            <button
              className="btn-sm"
              onClick={() => {
                clearOrgId();
                window.dispatchEvent(new Event("sentinel:org"));
                window.location.href = `${BASE_PATH}/`;
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
