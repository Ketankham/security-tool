// Thin typed client over the Sentinel control-plane API.
//
// Auth today is the dev stand-in: an X-Org-Id header (see
// apps/api/sentinel_api_app/deps.get_current_org). When Clerk lands this is
// the one place that swaps a header for a bearer token.

import type {
  DiscoveredPath,
  Finding,
  LoginTestResult,
  Organization,
  OrganizationSummary,
  OwnershipChallenge,
  OwnershipMethod,
  OwnershipVerifyResult,
  Persona,
  Scan,
  ScanAsset,
  ScanAuthorisation,
  ScanCreateBody,
  ScanEstimate,
  ScanRetryBody,
  ScanEndpoint,
  ToolRun,
  ScanEventsPage,
  ScopeRule,
  Target,
  TranscriptDoc,
  Whoami,
} from "./types";
import type { LoginRecipe } from "@/components/LoginRecipeFields";

const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE?.replace(/\/$/, "") || "http://localhost:8000";

// URL prefix the dashboard is mounted under (see next.config.mjs). Next adds it
// to <Link>/router.push itself; use this only for raw window.location moves.
export const BASE_PATH = (process.env.NEXT_PUBLIC_BASE_PATH || "").replace(/\/$/, "");

const ORG_KEY = "sentinel.orgId";

export function getOrgId(): string | null {
  if (typeof window === "undefined") return null;
  try {
    return window.localStorage.getItem(ORG_KEY);
  } catch {
    return null;
  }
}

export function setOrgId(id: string): void {
  try {
    window.localStorage.setItem(ORG_KEY, id);
  } catch {
    /* ignore: private mode / blocked storage */
  }
}

export function clearOrgId(): void {
  try {
    window.localStorage.removeItem(ORG_KEY);
  } catch {
    /* ignore */
  }
}

// FastAPI/Pydantic 422s carry a list of {loc, msg}; turn it into one
// readable line ("login_recipe.steps.0: step 'fill' needs: value") instead
// of showing the raw JSON to the user.
function formatDetail(detail: unknown): string {
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    return detail
      .map((d) => {
        const item = d as { loc?: unknown[]; msg?: string };
        const loc = (item.loc ?? []).filter((x) => x !== "body").join(".");
        const msg = (item.msg ?? JSON.stringify(d)).replace(/^Value error, /, "");
        return loc ? `${loc}: ${msg}` : msg;
      })
      .join("; ");
  }
  return JSON.stringify(detail);
}

export class ApiError extends Error {
  constructor(
    public status: number,
    public detail: string,
  ) {
    super(detail);
    this.name = "ApiError";
  }
}

async function request<T>(
  path: string,
  opts: { method?: string; body?: unknown; org?: boolean | "optional" } = {},
): Promise<T> {
  const { method = "GET", body, org = true } = opts;
  const headers: Record<string, string> = { "Content-Type": "application/json" };

  if (org === "optional") {
    // Endpoints that don't need an organization: send it if one is chosen.
    const orgId = getOrgId();
    if (orgId) headers["X-Org-Id"] = orgId;
  } else if (org) {
    const orgId = getOrgId();
    if (!orgId) throw new ApiError(401, "No organization selected.");
    headers["X-Org-Id"] = orgId;
  }

  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError(0, `Cannot reach the API at ${API_BASE}. Is it running?`);
  }

  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`;
    try {
      const data = await res.json();
      if (data?.detail) detail = formatDetail(data.detail);
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, detail);
  }

  if (res.status === 204) return undefined as T;
  // 202 Accepted (cancel) may come with no body.
  const text = await res.text();
  return (text ? JSON.parse(text) : undefined) as T;
}

export const api = {
  base: API_BASE,

  // Orgs. Creating an org does not need an org header (it mints one).
  createOrg: (name: string, slug: string) =>
    request<Organization>("/organizations", { method: "POST", body: { name, slug }, org: false }),
  me: () => request<Organization>("/organizations/me"),
  // Every organization, for the organization browser (no org header).
  listOrgs: () => request<OrganizationSummary[]>("/organizations", { org: false }),
  deleteOrg: (id: string) =>
    request<void>(`/organizations/${id}`, { method: "DELETE", org: false }),

  // Targets.
  listTargets: () => request<Target[]>("/targets"),
  getTarget: (id: string) => request<Target>(`/targets/${id}`),
  updateTarget: (id: string, body: { root_domain?: string; display_name?: string }) =>
    request<Target>(`/targets/${id}`, { method: "PATCH", body }),
  deleteTarget: (id: string) => request<void>(`/targets/${id}`, { method: "DELETE" }),
  createTarget: (body: { root_domain: string; display_name: string; is_production: boolean }) =>
    request<Target>("/targets", { method: "POST", body }),
  ownershipChallenge: (targetId: string, method: OwnershipMethod) =>
    request<OwnershipChallenge>(`/targets/${targetId}/ownership-challenge`, {
      method: "POST",
      body: { method },
    }),
  ownershipVerify: (targetId: string) =>
    request<OwnershipVerifyResult>(`/targets/${targetId}/ownership-verify`, { method: "POST" }),
  acceptAuthorization: (targetId: string) =>
    request<Target>(`/targets/${targetId}/authorization`, {
      method: "POST",
      body: { accepted: true },
    }),
  listScopeRules: (targetId: string) =>
    request<ScopeRule[]>(`/targets/${targetId}/scope-rules`),
  deleteScopeRule: (targetId: string, ruleId: string) =>
    request<void>(`/targets/${targetId}/scope-rules/${ruleId}`, { method: "DELETE" }),
  createScopeRule: (
    targetId: string,
    body: { kind: string; pattern: string; effect: string; label?: string },
  ) => request<ScopeRule>(`/targets/${targetId}/scope-rules`, { method: "POST", body }),

  // Personas.
  listPersonas: (targetId: string) => request<Persona[]>(`/targets/${targetId}/personas`),
  createPersona: (targetId: string, body: unknown) =>
    request<Persona>(`/targets/${targetId}/personas`, { method: "POST", body }),
  // The saved login recipe (never the password) for prefilling "Edit login".
  getPersonaLogin: (targetId: string, personaId: string) =>
    request<{ login_recipe: LoginRecipe | null; has_password: boolean }>(
      `/targets/${targetId}/personas/${personaId}/login`,
    ),
  // Set or replace an existing persona's login recipe and/or password.
  updatePersonaLogin: (targetId: string, personaId: string, body: unknown) =>
    request<Persona>(`/targets/${targetId}/personas/${personaId}`, { method: "PATCH", body }),
  deletePersona: (targetId: string, personaId: string) =>
    request<void>(`/targets/${targetId}/personas/${personaId}`, { method: "DELETE" }),
  // Test login (v1 #1): the worker replays the saved login; poll for the result.
  startLoginTest: (targetId: string, personaId: string) =>
    request<{ test_id: string }>(`/targets/${targetId}/personas/${personaId}/test-login`, {
      method: "POST",
    }),
  getLoginTest: (targetId: string, personaId: string, testId: string) =>
    request<LoginTestResult>(
      `/targets/${targetId}/personas/${personaId}/test-login/${testId}`,
    ),

  // Scans.
  listScans: (targetId: string) => request<Scan[]>(`/targets/${targetId}/scans`),
  getScan: (scanId: string) => request<Scan>(`/scans/${scanId}`),
  createScan: (targetId: string, options: ScanCreateBody = {}, triggeredBy = "manual") =>
    request<Scan>(`/targets/${targetId}/scans`, {
      method: "POST",
      body: { triggered_by: triggeredBy, ...options },
    }),
  // No body: retry as before. Scans that used active tools answer 409 unless
  // the body re-confirms the authorisation or drops the tools.
  retryScan: (scanId: string, body?: ScanRetryBody) =>
    request<Scan>(`/scans/${scanId}/retry`, { method: "POST", body }),
  // Cooperative: 202 means "asked to stop"; the scan finishes cancelling shortly.
  // 409 means it had already finished.
  cancelScan: (scanId: string) =>
    request<unknown>(`/scans/${scanId}/cancel`, { method: "POST" }),
  // The "I'm authorised" record for a scan (404 when it used no active tools).
  getScanAuthorisation: (scanId: string) =>
    request<ScanAuthorisation>(`/scans/${scanId}/authorisation`),

  // Who is signed in (via the sign-in proxy) and which active tools exist.
  whoami: () => request<Whoami>("/whoami", { org: "optional" }),
  // Worst-case duration/request estimate for a set of scan options.
  scanEstimate: (params: Record<string, string | boolean>) => {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) q.set(k, String(v));
    return request<ScanEstimate>(`/scan-estimate?${q.toString()}`, { org: "optional" });
  },

  // What a scan did (activity log, found endpoints, evidence).
  listScanEvents: (scanId: string, afterSeq = 0, limit = 2000) =>
    request<ScanEventsPage>(`/scans/${scanId}/events?after_seq=${afterSeq}&limit=${limit}`),
  listScanEndpoints: (scanId: string) => request<ScanEndpoint[]>(`/scans/${scanId}/endpoints`),
  listToolRuns: (scanId: string) => request<ToolRun[]>(`/scans/${scanId}/tool-runs`),
  listScanAssets: (scanId: string) => request<ScanAsset[]>(`/scans/${scanId}/assets`),
  // Paths found by directory brute force (confirmed first, then category, path).
  listScanPaths: (scanId: string) => request<DiscoveredPath[]>(`/scans/${scanId}/paths`),
  getTranscript: (scanId: string, transcriptId: string) =>
    request<TranscriptDoc>(`/scans/${scanId}/transcripts/${transcriptId}`),
  getScanReport: (scanId: string) =>
    request<Record<string, unknown>>(`/scans/${scanId}/report`),

  // Findings.
  listFindings: (scanId: string) => request<Finding[]>(`/scans/${scanId}/findings`),
};

/** Downloads an API text file. A plain link can't be used: the API needs
 * the X-Org-Id header, which only fetch can send. */
async function downloadText(path: string, filename: string): Promise<void> {
  const orgId = getOrgId();
  if (!orgId) throw new ApiError(401, "No organization selected.");
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, { headers: { "X-Org-Id": orgId } });
  } catch {
    throw new ApiError(0, `Cannot reach the API at ${API_BASE}. Is it running?`);
  }
  if (!res.ok) throw new ApiError(res.status, `${res.status} ${res.statusText}`);
  saveBlob(await res.blob(), filename);
}

/** The scan's activity log as a text file. */
export function downloadScanLog(scanId: string): Promise<void> {
  return downloadText(`/scans/${scanId}/events/download`, `scan-${scanId.slice(0, 8)}-log.txt`);
}

/** One tool run's full stdout or stderr as a text file. */
export function downloadToolOutput(
  scanId: string,
  run: { id: string; seq: number; tool: string },
  stream: "stdout" | "stderr",
): Promise<void> {
  const tool = run.tool.replace(/[^a-z0-9]+/gi, "-").replace(/^-|-$/g, "");
  return downloadText(
    `/scans/${scanId}/tool-runs/${run.id}/output?stream=${stream}`,
    `scan-${scanId.slice(0, 8)}-${run.seq}-${tool}-${stream}.txt`,
  );
}

/** Saves text/JSON the page already holds as a file. */
export function saveBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
