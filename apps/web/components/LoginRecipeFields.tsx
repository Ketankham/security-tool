"use client";

// The "how to log in as this persona" section, shared by Add persona and
// the per-persona "Set up login" editor. Produces the API's LoginRecipeIn
// (apps/api/.../schemas/persona.py) plus the password, which is sent as a
// separate encrypted credential and never placed inside the recipe: the
// recipe's fill_secret step only names it ("password").

export type SuccessKind = "url_contains" | "selector_visible" | "selector_hidden";

export interface LoginForm {
  loginUrl: string;
  usernameSelector: string;
  username: string;
  passwordSelector: string;
  password: string;
  submitSelector: string;
  successKind: SuccessKind;
  successValue: string;
  advanced: boolean;
  json: string;
  // The user confirmed the login page legitimately lives off the target's
  // domain (SSO). Required by the API for any off-domain navigation (QA #23).
  allowOffDomain: boolean;
}

export const EMPTY_LOGIN: LoginForm = {
  loginUrl: "",
  usernameSelector: "",
  username: "",
  passwordSelector: "",
  password: "",
  submitSelector: "button[type=submit]",
  successKind: "url_contains",
  successValue: "",
  advanced: false,
  json: "",
  allowOffDomain: false,
};

const CREDENTIAL_REF = "password";

export type LoginStepJson = Record<string, string | number | null | undefined>;

export type LoginRecipe = {
  start_url: string;
  steps: LoginStepJson[];
  success_assertion: { kind: SuccessKind; value: string; timeout_s?: number };
  allow_off_domain?: boolean;
  [extra: string]: unknown;
};

export type FieldErrors = Partial<Record<keyof LoginForm, string>>;

export type BuiltLogin =
  | { ok: true; recipe: LoginRecipe; password: string | null }
  | { ok: false; errors: FieldErrors };

// --- URL safety (mirrors sentinel_core.login_safety; the API re-checks) ----

function hostOf(url: string): string | null {
  try {
    const u = new URL(url);
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    return u.hostname.toLowerCase() || null;
  } catch {
    return null;
  }
}

function onTarget(host: string, rootDomain: string): boolean {
  const root = rootDomain.toLowerCase().replace(/\.$/, "");
  return host === root || host.endsWith(`.${root}`);
}

function urlProblem(url: string): string | null {
  const v = url.trim();
  if (!v) return "Enter the login page URL.";
  if (!/^https?:\/\//i.test(v)) return "The login page URL must start with http:// or https://.";
  if (!hostOf(v)) return "That URL has no valid host name.";
  return null;
}

/** Hosts the recipe would navigate to that aren't on the target. */
function offDomainHosts(recipe: { start_url?: unknown; steps?: unknown }, rootDomain: string): string[] {
  const urls = [String(recipe.start_url ?? "")];
  if (Array.isArray(recipe.steps)) {
    for (const s of recipe.steps as LoginStepJson[]) {
      if (s && s.action === "goto") urls.push(String(s.value ?? ""));
    }
  }
  const hosts = urls.map(hostOf).filter((h): h is string => !!h && !onTarget(h, rootDomain));
  return Array.from(new Set(hosts));
}

// --- building / validating ----------------------------------------------------

function simpleRecipe(f: LoginForm): LoginRecipe {
  const steps: LoginStepJson[] = [];
  if (f.usernameSelector.trim()) {
    steps.push({ action: "fill", selector: f.usernameSelector.trim(), value: f.username });
  }
  steps.push({ action: "fill_secret", selector: f.passwordSelector.trim(), credential_ref: CREDENTIAL_REF });
  steps.push({ action: "click", selector: f.submitSelector.trim() });
  return {
    start_url: f.loginUrl.trim(),
    steps,
    success_assertion: { kind: f.successKind, value: f.successValue.trim() },
  };
}

function parseJson(f: LoginForm): { recipe?: LoginRecipe; error?: string } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(f.json);
  } catch (e) {
    return { error: `Not valid JSON: ${(e as Error).message}` };
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { error: "Must be an object with start_url, steps and success_assertion." };
  }
  const r = parsed as LoginRecipe;
  if (!Array.isArray(r.steps) || r.steps.length === 0) return { error: "steps must be a non-empty list." };
  if (!r.steps.some((s) => s && s.action === "fill_secret")) {
    return { error: "Add a fill_secret step: it types the password below." };
  }
  if (!r.success_assertion || typeof r.success_assertion !== "object") {
    return { error: "success_assertion is missing." };
  }
  return { recipe: r };
}

/**
 * Every problem at once, keyed by field (QA #28), so the form can show them
 * all inline instead of one message per Save. `passwordRequired` is false
 * when editing a persona that already has a password stored.
 */
export function validateLogin(f: LoginForm, passwordRequired: boolean, rootDomain: string): FieldErrors {
  const errors: FieldErrors = {};
  let recipe: LoginRecipe | undefined;

  if (f.advanced) {
    const { recipe: r, error } = parseJson(f);
    if (error) errors.json = error;
    else {
      recipe = r;
      const urlErr = urlProblem(String(r!.start_url ?? ""));
      if (urlErr) errors.json = `start_url: ${urlErr}`;
    }
  } else {
    const urlErr = urlProblem(f.loginUrl);
    if (urlErr) errors.loginUrl = urlErr;
    if (f.usernameSelector.trim() && !f.username) errors.username = "Enter the username to type in.";
    if (!f.usernameSelector.trim() && f.username) {
      errors.usernameSelector = "Enter the username field's selector (e.g. #email), or clear the username.";
    }
    if (!f.passwordSelector.trim()) errors.passwordSelector = "Enter the password field's selector (e.g. #password).";
    if (!f.submitSelector.trim()) errors.submitSelector = "Enter the submit button's selector.";
    if (!f.successValue.trim()) errors.successValue = "Say how to tell the login worked (e.g. /dashboard).";
    if (!urlErr) recipe = simpleRecipe(f);
  }

  if (passwordRequired && !f.password) errors.password = "Enter the password for this login.";

  if (recipe && offDomainHosts(recipe, rootDomain).length > 0 && !f.allowOffDomain) {
    errors.allowOffDomain = "Confirm the other domain below, or use a login page on the target.";
  }
  return errors;
}

export function buildLogin(f: LoginForm, passwordRequired: boolean, rootDomain: string): BuiltLogin {
  const errors = validateLogin(f, passwordRequired, rootDomain);
  if (Object.keys(errors).length > 0) return { ok: false, errors };
  const base = f.advanced ? parseJson(f).recipe! : simpleRecipe(f);
  const recipe: LoginRecipe = { ...base, allow_off_domain: f.allowOffDomain };
  return { ok: true, recipe, password: f.password ? f.password : null };
}

// --- prefill from a saved recipe (QA #24) ----------------------------------------

// Stored JSONB comes back with keys re-ordered; put them in reading order.
const STEP_KEY_ORDER = ["action", "selector", "value", "credential_ref", "timeout_s"];

function cleanStep(s: LoginStepJson): LoginStepJson {
  const out: LoginStepJson = {};
  const keys = Object.keys(s).sort(
    (a, b) => (STEP_KEY_ORDER.indexOf(a) + 1 || 99) - (STEP_KEY_ORDER.indexOf(b) + 1 || 99),
  );
  for (const k of keys) {
    const v = s[k];
    if (v === null || v === undefined) continue;
    if (k === "timeout_s" && v === 10) continue;
    out[k] = v;
  }
  return out;
}

/** Saved recipe -> form. Uses the simple fields when the recipe has their
 * exact shape ([fill username], fill_secret, click); anything else opens in
 * the JSON editor so nothing is silently dropped. Password stays blank. */
export function loginFormFromRecipe(recipe: LoginRecipe | null): LoginForm {
  if (!recipe) return EMPTY_LOGIN;
  const steps = (recipe.steps ?? []).map(cleanStep);
  const allowOffDomain = !!recipe.allow_off_domain;
  const assertion = recipe.success_assertion ?? { kind: "url_contains", value: "" };

  const fill = steps.length === 3 ? steps[0] : null;
  const [secret, click] = steps.length === 3 ? steps.slice(1) : steps;
  const simple =
    (steps.length === 2 || steps.length === 3) &&
    (!fill || (fill.action === "fill" && Object.keys(fill).length === 3)) &&
    secret?.action === "fill_secret" &&
    secret.credential_ref === CREDENTIAL_REF &&
    Object.keys(secret).length === 3 &&
    click?.action === "click" &&
    Object.keys(click).length === 2 &&
    (assertion.timeout_s === undefined || assertion.timeout_s === 10) &&
    (recipe.max_duration_s === undefined || recipe.max_duration_s === 30);

  if (simple) {
    return {
      ...EMPTY_LOGIN,
      loginUrl: recipe.start_url ?? "",
      usernameSelector: String(fill?.selector ?? ""),
      username: String(fill?.value ?? ""),
      passwordSelector: String(secret!.selector ?? ""),
      submitSelector: String(click!.selector ?? ""),
      successKind: assertion.kind,
      successValue: assertion.value ?? "",
      allowOffDomain,
    };
  }
  const {
    allow_off_domain: _omit,
    steps: _rawSteps,
    strategy,
    start_url,
    success_assertion,
    ...rest
  } = recipe;
  void _omit;
  void _rawSteps;
  const forJson = {
    start_url,
    steps,
    success_assertion,
    ...rest,
    ...(strategy && strategy !== "form" ? { strategy } : {}),
  };
  return { ...EMPTY_LOGIN, advanced: true, json: JSON.stringify(forJson, null, 2), allowOffDomain };
}

// --- component ---------------------------------------------------------------------

function FieldError({ msg }: { msg?: string }) {
  if (!msg) return null;
  return (
    <div className="field-error" role="alert">
      {msg}
    </div>
  );
}

export function LoginRecipeFields({
  value,
  onChange,
  rootDomain,
  passwordHint,
  passwordRequired,
  showErrors,
}: {
  value: LoginForm;
  onChange: (next: LoginForm) => void;
  rootDomain: string;
  passwordHint?: string;
  passwordRequired: boolean;
  // Set after the first Save attempt: from then on every problem is shown
  // inline and updates as the user types (QA #28). URL problems that make a
  // recipe unsafe (QA #23) are shown immediately regardless.
  showErrors: boolean;
}) {
  const set = <K extends keyof LoginForm>(k: K, v: LoginForm[K]) => onChange({ ...value, [k]: v });
  const errors = validateLogin(value, passwordRequired, rootDomain);
  const err = (k: keyof LoginForm) => (showErrors ? errors[k] : undefined);

  // Unsafe-URL feedback doesn't wait for Save (QA #23): javascript:, data:,
  // missing host — once something has been typed.
  const liveUrlError = !value.advanced && value.loginUrl.trim() ? urlProblem(value.loginUrl) : null;

  let candidate: { start_url?: unknown; steps?: unknown } | null = null;
  if (value.advanced) candidate = parseJson(value).recipe ?? null;
  else if (!urlProblem(value.loginUrl)) candidate = { start_url: value.loginUrl.trim(), steps: [] };
  const offHosts = candidate ? offDomainHosts(candidate, rootDomain) : [];

  function toggleAdvanced() {
    if (!value.advanced) {
      // Seed the JSON with whatever the simple fields already describe.
      onChange({ ...value, advanced: true, json: JSON.stringify(simpleRecipe(value), null, 2) });
    } else {
      onChange({ ...value, advanced: false });
    }
  }

  return (
    <div>
      {!value.advanced ? (
        <>
          <div className="row">
            <div>
              <label>Login page URL *</label>
              <input
                value={value.loginUrl}
                placeholder={`https://${rootDomain}/login`}
                aria-invalid={!!(liveUrlError || err("loginUrl"))}
                onChange={(e) => set("loginUrl", e.target.value)}
              />
              <FieldError msg={liveUrlError ?? err("loginUrl")} />
            </div>
          </div>
          <div className="row">
            <div>
              <label>Username field (CSS selector)</label>
              <input
                className="mono"
                value={value.usernameSelector}
                placeholder="#email"
                onChange={(e) => set("usernameSelector", e.target.value)}
              />
              <FieldError msg={err("usernameSelector")} />
            </div>
            <div>
              <label>Username</label>
              <input
                value={value.username}
                autoComplete="off"
                placeholder="member@client.com"
                onChange={(e) => set("username", e.target.value)}
              />
              <FieldError msg={err("username")} />
            </div>
          </div>
        </>
      ) : (
        <div className="row">
          <div>
            <label>Login recipe (JSON)</label>
            <textarea
              className="mono"
              rows={14}
              value={value.json}
              spellCheck={false}
              onChange={(e) => set("json", e.target.value)}
              style={{ width: "100%" }}
            />
            <FieldError msg={err("json")} />
            <div className="hint">
              Steps run in order after opening <span className="mono">start_url</span>. Actions:{" "}
              <span className="mono">fill</span> (selector, value), <span className="mono">fill_secret</span>{" "}
              (selector, credential_ref — types the password below), <span className="mono">click</span>,{" "}
              <span className="mono">wait_for_selector</span> (selector), <span className="mono">goto</span>,{" "}
              <span className="mono">wait_for_url</span> (value). Use this for two-page logins (email → Next
              → password).
            </div>
          </div>
        </div>
      )}

      {offHosts.length > 0 && (
        <div className="notice" style={{ marginTop: 8 }}>
          This login opens <span className="mono">{offHosts.join(", ")}</span>, which isn&apos;t{" "}
          <span className="mono">{rootDomain}</span> or one of its subdomains. The password will be typed
          into that page.
          <label style={{ display: "flex", gap: 8, alignItems: "center", marginTop: 8 }}>
            <input
              type="checkbox"
              checked={value.allowOffDomain}
              onChange={(e) => set("allowOffDomain", e.target.checked)}
              style={{ width: "auto" }}
            />
            This is the client&apos;s real login page (e.g. their SSO provider), and they&apos;ve authorised it.
          </label>
          <FieldError msg={err("allowOffDomain")} />
        </div>
      )}

      <div className="row">
        {!value.advanced && (
          <div>
            <label>Password field (CSS selector) *</label>
            <input
              className="mono"
              value={value.passwordSelector}
              placeholder="#password"
              onChange={(e) => set("passwordSelector", e.target.value)}
            />
            <FieldError msg={err("passwordSelector")} />
          </div>
        )}
        <div>
          <label>Password (stored encrypted){passwordRequired ? " *" : ""}</label>
          <input
            type="password"
            value={value.password}
            autoComplete="new-password"
            placeholder={passwordHint}
            onChange={(e) => set("password", e.target.value)}
          />
          <FieldError msg={err("password")} />
        </div>
      </div>

      {!value.advanced && (
        <div className="row">
          <div>
            <label>Submit button (CSS selector) *</label>
            <input
              className="mono"
              value={value.submitSelector}
              onChange={(e) => set("submitSelector", e.target.value)}
            />
            <FieldError msg={err("submitSelector")} />
          </div>
          <div>
            <label>Login succeeded if *</label>
            <div style={{ display: "flex", gap: 6 }}>
              <select
                value={value.successKind}
                onChange={(e) => set("successKind", e.target.value as SuccessKind)}
                style={{ maxWidth: 170 }}
              >
                <option value="url_contains">URL contains</option>
                <option value="selector_visible">element is visible</option>
                <option value="selector_hidden">element is gone</option>
              </select>
              <input
                className={value.successKind === "url_contains" ? undefined : "mono"}
                value={value.successValue}
                placeholder={value.successKind === "url_contains" ? "/dashboard" : "#logout"}
                onChange={(e) => set("successValue", e.target.value)}
              />
            </div>
            <FieldError msg={err("successValue")} />
          </div>
        </div>
      )}

      <div className="hint" style={{ marginTop: 6 }}>
        Finding selectors: open the login page in Chrome, right-click the field → <b>Inspect</b>, and
        use its id (<span className="mono">id=&quot;email&quot;</span> →{" "}
        <span className="mono">#email</span>) or name (
        <span className="mono">input[name=email]</span>). Logins behind CAPTCHA or one-time codes
        can&apos;t be automated — ask the client for a test account without them.{" "}
        <button className="btn-sm" type="button" onClick={toggleAdvanced}>
          {value.advanced ? "Back to simple fields" : "Advanced: edit steps as JSON"}
        </button>
      </div>
    </div>
  );
}
