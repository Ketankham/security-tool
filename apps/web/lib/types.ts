// Types mirror the API's Pydantic schemas (apps/api/sentinel_api_app/schemas).
// Kept in sync by hand for now; a generated client is a later nicety.

export type OrgRole = "owner" | "admin" | "member" | "viewer";

export interface Organization {
  id: string;
  name: string;
  slug: string;
  plan: string;
}

export type OwnershipMethod = "dns_txt" | "well_known_file" | "meta_tag";

export interface Target {
  id: string;
  root_domain: string;
  display_name: string;
  is_production: boolean;
  ownership_verified: boolean;
  ownership_verification_method: OwnershipMethod | null;
  ownership_verified_at: string | null;
  authorization_accepted: boolean;
  is_scannable: boolean;
}

export interface OwnershipChallenge {
  method: OwnershipMethod;
  token: string;
  instructions: string;
}

export interface OwnershipVerifyResult {
  verified: boolean;
  detail: string;
}

export interface ScopeRule {
  id: string;
  kind: "host" | "path_prefix" | "path_regex" | "method";
  pattern: string;
  effect: "include" | "exclude";
  label: string;
}

export type LoginStrategy =
  | "form"
  | "oauth_redirect"
  | "saml"
  | "api_token"
  | "har_replay"
  | "manual_session";

export interface Persona {
  id: string;
  label: string;
  role_name: string;
  trust_rank: number;
  tenant_key: string | null;
  login_strategy: LoginStrategy | null;
  is_available: boolean;
  unavailable_reason: string | null;
  expected_denied: string[];
  has_login_recipe: boolean;
}

// --- Scans ---

export type ScanState =
  | "queued"
  | "scope_verifying"
  | "blocked_unverified"
  | "recon"
  | "auth_establishing"
  | "failed_auth"
  | "crawling"
  | "surface_mapping"
  | "passive_checks"
  | "testing"
  | "verifying"
  | "triaging"
  | "reporting"
  | "complete"
  | "paused"
  | "cancelled"
  | "failed";

export type PhaseName =
  | "scope_verifying"
  | "recon"
  | "auth_establishing"
  | "crawling"
  | "surface_mapping"
  | "passive_checks"
  | "active_injection"
  | "access_control"
  | "session_checks"
  | "business_logic"
  | "verifying"
  | "triaging"
  | "reporting";

export type PhaseStatus = "pending" | "running" | "completed" | "failed" | "skipped";

export interface ScanPhase {
  name: PhaseName;
  status: PhaseStatus;
  started_at: string | null;
  finished_at: string | null;
  error: string | null;
  stats_json: Record<string, unknown>;
}

export interface Scan {
  id: string;
  target_id: string;
  state: ScanState;
  triggered_by: string;
  is_degraded: boolean;
  degraded_reasons: string[];
  fail_reason: string | null;
  started_at: string | null;
  finished_at: string | null;
  llm_tokens_used: number;
  llm_token_budget: number;
  phases: ScanPhase[];
}

// --- Findings ---

export type FindingSeverity = "critical" | "high" | "medium" | "low" | "info";
export type FindingConfidence = "confirmed" | "probable" | "informational";
export type FindingStatus =
  | "open"
  | "fixed"
  | "regressed"
  | "accepted_risk"
  | "false_positive";

export interface Verification {
  reproduced_count: number;
  attempted_count: number;
  passed: boolean;
}

export interface Evidence {
  transcript_id: string;
  role: string;
  note: string;
}

export interface Finding {
  id: string;
  scan_id: string;
  fingerprint: string;
  rule_id: string;
  title: string;
  cwe: number[];
  owasp_top10: string | null;
  cvss_vector: string | null;
  severity: FindingSeverity;
  confidence: FindingConfidence;
  status: FindingStatus;
  narrative: string;
  remediation: Record<string, unknown>;
  reproduction: Record<string, unknown>;
  evidence: Evidence[];
  verification: Verification | null;
}
