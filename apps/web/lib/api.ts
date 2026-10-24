// Thin typed client over the Sentinel control-plane API.
//
// Auth today is the dev stand-in: an X-Org-Id header (see
// apps/api/sentinel_api_app/deps.get_current_org). When Clerk lands this is
// the one place that swaps a header for a bearer token.

import type {
  Finding,
  Organization,
  OwnershipChallenge,
  OwnershipMethod,
  OwnershipVerifyResult,
  Persona,
  Scan,
  ScopeRule,
  Target,
} from "./types";

const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE?.replace(/\/$/, "") || "http://localhost:8000";

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
  opts: { method?: string; body?: unknown; org?: boolean } = {},
): Promise<T> {
  const { method = "GET", body, org = true } = opts;
  const headers: Record<string, string> = { "Content-Type": "application/json" };

  if (org) {
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
      if (data?.detail) detail = typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail);
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, detail);
  }

  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export const api = {
  base: API_BASE,

  // Orgs. Creating an org does not need an org header (it mints one).
  createOrg: (name: string, slug: string) =>
    request<Organization>("/organizations", { method: "POST", body: { name, slug }, org: false }),
  me: () => request<Organization>("/organizations/me"),

  // Targets.
  listTargets: () => request<Target[]>("/targets"),
  getTarget: (id: string) => request<Target>(`/targets/${id}`),
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
  createScopeRule: (
    targetId: string,
    body: { kind: string; pattern: string; effect: string; label?: string },
  ) => request<ScopeRule>(`/targets/${targetId}/scope-rules`, { method: "POST", body }),

  // Personas.
  listPersonas: (targetId: string) => request<Persona[]>(`/targets/${targetId}/personas`),
  createPersona: (targetId: string, body: unknown) =>
    request<Persona>(`/targets/${targetId}/personas`, { method: "POST", body }),

  // Scans.
  listScans: (targetId: string) => request<Scan[]>(`/targets/${targetId}/scans`),
  getScan: (scanId: string) => request<Scan>(`/scans/${scanId}`),
  createScan: (targetId: string, triggeredBy = "manual") =>
    request<Scan>(`/targets/${targetId}/scans`, {
      method: "POST",
      body: { triggered_by: triggeredBy },
    }),

  // Findings.
  listFindings: (scanId: string) => request<Finding[]>(`/scans/${scanId}/findings`),
};
