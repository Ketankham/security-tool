// Types mirror the API's Pydantic schemas (apps/api/sentinel_api_app/schemas).
// Kept in sync by hand for now; a generated client is a later nicety.

export type OrgRole = "owner" | "admin" | "member" | "viewer";

export interface OrganizationSummary {
  id: string;
  name: string;
  slug: string;
  target_count: number;
  target_domains: string[];
}

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
  // False when this deployment has the ownership gate switched off.
  ownership_check_required: boolean;
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

export interface LoginTestResult {
  status: "pending" | "done";
  success: boolean | null;
  error: string | null;
  final_url: string | null;
  screenshot_jpeg_b64: string | null;
  duration_s: number | null;
  checked_at: string | null;
}

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

export type ScanSpeed = "gentle" | "normal" | "fast";
export type ScanDepth = "quick" | "standard" | "deep";
export type ReconProfile = "light" | "full";
export type Wordlist = "sentinel-core" | "seclists-common";
export type TargetEnvironment = "production" | "staging";
export type ActiveToolKey = "dir_bruteforce" | "port_scan" | "all_ports";

export interface ScanOptions {
  speed?: ScanSpeed;
  depth?: ScanDepth;
  recon_profile?: ReconProfile;
  // Active tools (need an identity and an authorisation record).
  dir_bruteforce?: boolean;
  port_scan?: boolean;
  all_ports?: boolean;
  wordlist?: Wordlist;
  target_environment?: TargetEnvironment;
}

export interface Scan {
  id: string;
  target_id: string;
  state: ScanState;
  triggered_by: string;
  is_degraded: boolean;
  degraded_reasons: string[];
  fail_reason: string | null;
  options: ScanOptions;
  // Who launched the scan (verified sign-in name). Null/absent on scans from
  // before identity existed, or when the API has no identity.
  requested_by?: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  llm_tokens_used: number;
  llm_token_budget: number;
  phases: ScanPhase[];
}

// --- Identity, estimates and authorisation (active tools) ---

export interface AuthorisationStatement {
  version: string;
  // Both contain {client} and {target} placeholders.
  template: string;
  all_ports_template: string;
}

export interface Whoami {
  username: string | null;
  source: string | null;
  // Active tools this deployment can run. The UI shows only these.
  available_tools: string[];
  statement?: AuthorisationStatement | null;
}

// The estimate's exact shape is owned by sentinel_core.scan_options.estimate();
// the UI renders whatever numbers it returns (see lib/activeTools.ts).
export type ScanEstimate = Record<string, unknown>;

export interface AuthorisationIn {
  accepted: boolean;
  client_name: string;
  statement_version: string;
  all_ports_confirmed: boolean;
}

export interface ScanAuthorisation {
  id: string;
  scan_id: string;
  target_id: string;
  username: string;
  accepted_at: string;
  statement_version: string;
  statement_text: string;
  client_name: string;
  target_name: string;
  tools: string[];
  all_ports_confirmed: boolean;
  target_environment: TargetEnvironment | string;
  options_snapshot: Record<string, unknown>;
  client_ip: string | null;
  user_agent: string | null;
  carried_over_from_scan_id: string | null;
  created_at?: string;
  updated_at?: string;
}

export interface ScanCreateBody {
  speed?: ScanSpeed;
  depth?: ScanDepth;
  recon_profile?: ReconProfile;
  dir_bruteforce?: boolean;
  port_scan?: boolean;
  all_ports?: boolean;
  wordlist?: Wordlist;
  target_environment?: TargetEnvironment;
  authorisation?: AuthorisationIn;
}

export interface ScanRetryBody {
  authorisation?: AuthorisationIn;
  drop_active_tools?: boolean;
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

// --- Scan insight: activity log, found endpoints, evidence ---

export interface ScanEvent {
  seq: number;
  at: string;
  stage: string;
  level: "info" | "warn" | "error";
  persona: string | null;
  message: string;
  data: Record<string, unknown>;
}

export interface ScanEventsPage {
  events: ScanEvent[];
  total: number;
  last_seq: number;
}

export interface ScanEndpoint {
  host: string;
  method: string;
  path_template: string;
  source: string;
  persona_ids: string[];
}

export interface ToolRun {
  id: string;
  seq: number;
  phase: string;
  tool: string;
  binary: string | null;
  version: string | null;
  command: string;
  status: "ok" | "failed" | "timed_out" | "not_installed" | "skipped" | string;
  skip_reason: string | null;
  started_at: string | null;
  finished_at: string | null;
  duration_ms: number | null;
  exit_code: number | null;
  timed_out: boolean;
  results_count: number;
  stdout_chars: number;
  stderr_chars: number;
  stdout_truncated: boolean;
  stderr_truncated: boolean;
  stdout_preview: string;
  stderr_preview: string;
}

export interface HttpProbe {
  url: string;
  status_code: number | null;
  title?: string | null;
  server?: string | null;
  tech?: string[];
  error?: string | null;
  cdn?: string | null;
  content_type?: string | null;
}

export interface ScanAsset {
  host: string;
  discovery_source: string;
  sources: string[];
  scope_status: "in_scope" | "excluded" | "private_ip" | "unresolved" | "capped" | string;
  scope_reason: string | null;
  ip_addresses: string[];
  live: boolean;
  tech: string[];
  http_probes: HttpProbe[];
  endpoints: number;
}

export interface TranscriptDoc {
  request?: { method?: string; url?: string; headers?: Record<string, string>; body?: string | null };
  response?: {
    status_code?: number;
    headers?: Record<string, string>;
    body?: string | null;
    elapsed_ms?: number;
  } | null;
  error?: string | null;
  recorded_at?: string;
}
