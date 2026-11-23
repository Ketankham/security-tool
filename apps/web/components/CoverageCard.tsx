"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { CHECK_PHASES, PHASE_LABEL, crawlStats } from "@/lib/scan";
import type { Persona, Scan } from "@/lib/types";

const SPEED_TEXT: Record<string, string> = { gentle: "gentle (2 req/s)", normal: "normal (5 req/s)", fast: "fast (10 req/s)" };
const DEPTH_TEXT: Record<string, string> = { quick: "quick (30 pages)", standard: "standard (100 pages)", deep: "deep (300 pages)" };

// QA #38: say plainly what this scan did and did not look at, so "0 findings"
// on a scan that crawled one page and skipped most checks isn't read as clean.
export function CoverageCard({ scan }: { scan: Scan }) {
  const [personas, setPersonas] = useState<Persona[] | null>(null);
  useEffect(() => {
    api.listPersonas(scan.target_id).then(setPersonas).catch(() => setPersonas([]));
  }, [scan.target_id]);
  const label = (id: string) =>
    id === "anonymous" ? "Logged-out visitor" : (personas?.find((p) => p.id === id)?.label ?? id.slice(0, 8));

  const { pagesByPersona, endpointsByPersona } = crawlStats(scan);
  const crawled = Object.keys(pagesByPersona).length > 0;
  const maxPages = Math.max(0, ...Object.values(pagesByPersona));
  const auth = scan.phases.find((p) => p.name === "auth_establishing")?.stats_json as
    | { personas_configured?: number; personas_available?: number }
    | undefined;
  const ran = scan.phases.filter((p) => CHECK_PHASES.includes(p.name) && p.status === "completed");
  const skipped = scan.phases.filter((p) => CHECK_PHASES.includes(p.name) && p.status === "skipped");

  return (
    <div className="card" style={{ marginTop: 16 }}>
      <h2>What this scan covered</h2>
      {crawled && maxPages <= 2 && (
        <div className="error-box" style={{ marginBottom: 10 }}>
          The crawl only reached {maxPages} page{maxPages === 1 ? "" : "s"}, so these results cover
          very little of the site. Check the target domain (e.g. the app may live on{" "}
          <span className="mono">www.</span>) and that the logins work (Test login), then run again.
        </div>
      )}
      <ul style={{ margin: 0, paddingLeft: 18, lineHeight: 1.7 }}>
        {(scan.options?.speed || scan.options?.depth) && (
          <li>
            Settings: speed {SPEED_TEXT[scan.options.speed ?? "normal"]}, depth{" "}
            {DEPTH_TEXT[scan.options.depth ?? "standard"]}, recon{" "}
            {scan.options.recon_profile === "full" ? "full" : "light"}
          </li>
        )}
        {auth && (auth.personas_configured ?? 0) > 0 && (
          <li>
            Logins: {auth.personas_available ?? 0} of {auth.personas_configured} worked
          </li>
        )}
        {crawled && (
          <li>
            Crawled:{" "}
            {Object.entries(pagesByPersona)
              .map(([id, n]) => `${label(id)}: ${n} page${n === 1 ? "" : "s"}, ${endpointsByPersona[id] ?? 0} endpoints`)
              .join(" · ")}
          </li>
        )}
        <li>
          Checks run: {ran.length ? ran.map((p) => PHASE_LABEL[p.name]).join(", ") : "none yet"}
        </li>
        {skipped.length > 0 && (
          <li>
            <b>Not checked</b> (not built yet, or out of v1):{" "}
            {skipped.map((p) => PHASE_LABEL[p.name]).join(", ")}. Zero findings says nothing about these.
          </li>
        )}
      </ul>
    </div>
  );
}
