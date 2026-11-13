"use client";

// The "how to log in as this persona" section, shared by Add persona and
// the per-persona "Set up login" editor. Produces the API's LoginRecipeIn
// (apps/api/.../schemas/persona.py) plus the secret, which is sent as a
// separate encrypted credential and never placed inside the recipe.
//
// Three methods (v1 #1):
//   form   — the worker types a username + password into the login page;
//   cookie — the tester logs in by hand and pastes the Cookie header value;
//   header — the tester pastes one request header (e.g. Authorization: Bearer …).
// cookie/header are for logins a script can't get through (CAPTCHA, SSO, OTP).

export type SuccessKind = "url_contains" | "url_not_contains" | "selector_visible" | "selector_hidden";
export type LoginMethod = "form" | "cookie" | "header";

export interface LoginForm {
  method: LoginMethod;
  // form: the login page. cookie/header: a page only a logged-in user sees.
  loginUrl: string;
  usernameSelector: string;
  username: string;
  passwordSelector: string;
  // The secret: password (form), Cookie header value, or header value.
  password: string;
  submitSelector: string;
  successKind: SuccessKind;
  successValue: string;
  headerName: string;
  advanced: boolean;
  json: string;
  // The user confirmed the login page legitimately lives off the target's
  // domain (SSO). Required by the API for any off-domain navigation (QA #23).
  allowOffDomain: boolean;
  // The method of the login as saved (null when nothing is saved yet).
  // Switching method needs a new secret: a stored password is not a cookie.
  savedMethod: LoginMethod | null;
}

export const EMPTY_LOGIN: LoginForm = {
  method: "form",
  loginUrl: "",
  usernameSelector: "",
  username: "",
  passwordSelector: "",
  password: "",
  submitSelector: "button[type=submit]",
  successKind: "url_contains",
  successValue: "",
  headerName: "Authorization",
  advanced: false,
  json: "",
  allowOffDomain: false,
  savedMethod: null,
};

const CREDENTIAL_REF = "password";

export const METHOD_LABEL: Record<LoginMethod, string> = {
  form: "Login form",
  cookie: "Pasted cookie",
  header: "Pasted header",
};

const SECRET_LABEL: Record<LoginMethod, string> = {
  form: "Password",
  cookie: "Cookie value",
  header: "Header value",
};

export type LoginStepJson = Record<string, string | number | null | undefined>;

export type LoginRecipe = {
  strategy?: LoginMethod;
  start_url: string;
  steps: LoginStepJson[];
  success_assertion: { kind: SuccessKind; value: string; timeout_s?: number };
  header_name?: string | null;
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

function urlProblem(url: string, what = "login page URL"): string | null {
  const v = url.trim();
  if (!v) return `Enter the ${what}.`;
  if (!/^https?:\/\//i.test(v)) return `The ${what} must start with http:// or https://.`;
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

// --- pasted sessions (mirrors sentinel_core.session_import) --------------------

const TOKEN_RE = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const FORBIDDEN_HEADERS = new Set([
  "host", "cookie", "content-length", "content-type", "transfer-encoding", "connection",
  "upgrade", "te", "trailer", "keep-alive", "proxy-authorization", "proxy-connection",
]);

function cookieProblem(raw: string): string | null {
  let text = raw.trim();
  if (/^cookie:/i.test(text)) text = text.slice(7).trim();
  if (!text) return "Paste at least one cookie, e.g. sessionid=abc123";
  if (/[\r\n]/.test(text)) return "The cookie value must be on a single line.";
  for (const part of text.split(";").map((p) => p.trim()).filter(Boolean)) {
    const eq = part.indexOf("=");
    const name = eq > 0 ? part.slice(0, eq).trim() : "";
    if (!name) return `"${part.slice(0, 40)}" is not a name=value cookie.`;
    if (!TOKEN_RE.test(name)) return `"${name.slice(0, 40)}" is not a valid cookie name.`;
  }
  return null;
}

function headerNameProblem(name: string): string | null {
  const n = name.trim();
  if (!n) return "Enter the header name, e.g. Authorization";
  if (!TOKEN_RE.test(n)) return "That is not a valid header name (no spaces or colons).";
  if (n.toLowerCase() === "cookie") return "Use “Pasted cookie” for cookies.";
  if (FORBIDDEN_HEADERS.has(n.toLowerCase())) return `The ${n} header can't be used for logging in.`;
  return null;
}

function headerValueProblem(value: string): string | null {
  if (!value.trim()) return "Paste the header value, e.g. Bearer eyJhbGci…";
  if (/[\r\n]/.test(value.trim())) return "The header value must be on a single line.";
  return null;
}

// --- building / validating ----------------------------------------------------

function simpleRecipe(f: LoginForm): LoginRecipe {
  if (f.method !== "form") {
    return {
      strategy: f.method,
      start_url: f.loginUrl.trim(),
      steps: [],
      success_assertion: { kind: f.successKind, value: f.successValue.trim() },
      ...(f.method === "header" ? { header_name: f.headerName.trim() } : {}),
    };
  }
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

/** Whether a new secret must be entered: nothing stored yet, or the method
 * changed since the login was saved. */
export function secretRequired(f: LoginForm, passwordRequired: boolean): boolean {
  return passwordRequired || (f.savedMethod !== null && f.savedMethod !== f.method);
}

/**
 * Every problem at once, keyed by field (QA #28), so the form can show them
 * all inline instead of one message per Save. `passwordRequired` is false
 * when editing a persona that already has a secret stored.
 */
export function validateLogin(f: LoginForm, passwordRequired: boolean, rootDomain: string): FieldErrors {
  const errors: FieldErrors = {};
  let recipe: LoginRecipe | undefined;
  const needSecret = secretRequired(f, passwordRequired);

  if (f.method !== "form") {
    const urlErr = urlProblem(f.loginUrl, "page to check");
    if (urlErr) errors.loginUrl = urlErr;
    else {
      const host = hostOf(f.loginUrl.trim());
      if (host && !onTarget(host, rootDomain)) {
        errors.loginUrl = `Use a page on ${rootDomain}: a pasted session is only ever sent to the target's own site.`;
      }
    }
    if (!f.successValue.trim()) errors.successValue = "Say how to tell the session works (e.g. URL doesn't contain /login).";
    if (f.method === "header") {
      const hErr = headerNameProblem(f.headerName);
      if (hErr) errors.headerName = hErr;
    }
    if (f.password || needSecret) {
      const sErr = f.method === "cookie" ? cookieProblem(f.password) : headerValueProblem(f.password);
      if (sErr) errors.password = sErr;
    }
    return errors;
  }

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

  if (needSecret && !f.password) errors.password = "Enter the password for this login.";

  if (recipe && offDomainHosts(recipe, rootDomain).length > 0 && !f.allowOffDomain) {
    errors.allowOffDomain = "Confirm the other domain below, or use a login page on the target.";
  }
  return errors;
}

export function buildLogin(f: LoginForm, passwordRequired: boolean, rootDomain: string): BuiltLogin {
  const errors = validateLogin(f, passwordRequired, rootDomain);
  if (Object.keys(errors).length > 0) return { ok: false, errors };
  if (f.method !== "form") {
    return { ok: true, recipe: simpleRecipe(f), password: f.password.trim() ? f.password.trim() : null };
  }
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
 * the JSON editor so nothing is silently dropped. The secret stays blank. */
export function loginFormFromRecipe(recipe: LoginRecipe | null): LoginForm {
  if (!recipe) return EMPTY_LOGIN;
  const method: LoginMethod =
    recipe.strategy === "cookie" || recipe.strategy === "header" ? recipe.strategy : "form";
  const assertion = recipe.success_assertion ?? { kind: "url_contains", value: "" };

  if (method !== "form") {
    return {
      ...EMPTY_LOGIN,
      method,
      savedMethod: method,
      loginUrl: recipe.start_url ?? "",
      successKind: assertion.kind,
      successValue: assertion.value ?? "",
      headerName: recipe.header_name || "Authorization",
    };
  }

  const steps = (recipe.steps ?? []).map(cleanStep);
  const allowOffDomain = !!recipe.allow_off_domain;
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
      savedMethod: "form",
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
    strategy: _strategy,
    header_name: _header,
    start_url,
    success_assertion,
    ...rest
  } = recipe;
  void _omit;
  void _rawSteps;
  void _strategy;
  void _header;
  const forJson = { start_url, steps, success_assertion, ...rest };
  return {
    ...EMPTY_LOGIN,
    savedMethod: "form",
    advanced: true,
    json: JSON.stringify(forJson, null, 2),
    allowOffDomain,
  };
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

const SUCCESS_PLACEHOLDER: Record<SuccessKind, string> = {
  url_contains: "/dashboard",
  url_not_contains: "/login",
  selector_visible: "#logout",
  selector_hidden: "#login-form",
};

function SuccessCheck({
  value,
  set,
  error,
}: {
  value: LoginForm;
  set: <K extends keyof LoginForm>(k: K, v: LoginForm[K]) => void;
  error?: string;
}) {
  const isUrl = value.successKind === "url_contains" || value.successKind === "url_not_contains";
  return (
    <div>
      <label>{value.method === "form" ? "Login succeeded if *" : "Session works if *"}</label>
      <div style={{ display: "flex", gap: 6 }}>
        <select
          value={value.successKind}
          onChange={(e) => set("successKind", e.target.value as SuccessKind)}
          style={{ maxWidth: 190 }}
          aria-label="Success check"
        >
          <option value="url_contains">URL contains</option>
          <option value="url_not_contains">URL doesn&apos;t contain</option>
          <option value="selector_visible">element is visible</option>
          <option value="selector_hidden">element is gone</option>
        </select>
        <input
          className={isUrl ? undefined : "mono"}
          value={value.successValue}
          placeholder={SUCCESS_PLACEHOLDER[value.successKind]}
          aria-label="Success check value"
          onChange={(e) => set("successValue", e.target.value)}
        />
      </div>
      <FieldError msg={error} />
      {value.successKind === "url_not_contains" && (
        <div className="hint">
          Passes if, after the page settles, the browser is <i>not</i> on a URL containing this — e.g.{" "}
          <span className="mono">/sign-in</span> when a dead session gets sent back to the sign-in page.
        </div>
      )}
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
  const needSecret = secretRequired(value, passwordRequired);
  const switching = value.savedMethod !== null && value.savedMethod !== value.method;

  function chooseMethod(method: LoginMethod) {
    if (method === value.method) return;
    const next: LoginForm = { ...value, method, password: "" };
    // A pasted session is usually checked by "not bounced to the login page".
    if (method !== "form" && !value.successValue.trim()) next.successKind = "url_not_contains";
    if (method === "form" && !value.successValue.trim()) next.successKind = "url_contains";
    onChange(next);
  }

  return (
    <div>
      <div role="radiogroup" aria-label="Login method" style={{ display: "flex", gap: 6, flexWrap: "wrap", margin: "8px 0" }}>
        {(["form", "cookie", "header"] as LoginMethod[]).map((m) => (
          <button
            key={m}
            type="button"
            role="radio"
            aria-checked={value.method === m}
            className={value.method === m ? "btn-sm btn-primary" : "btn-sm"}
            onClick={() => chooseMethod(m)}
          >
            {METHOD_LABEL[m]}
          </button>
        ))}
      </div>
      {switching && (
        <div className="notice" style={{ marginBottom: 8 }}>
          Switching from {METHOD_LABEL[value.savedMethod!].toLowerCase()} to{" "}
          {METHOD_LABEL[value.method].toLowerCase()}: enter the {SECRET_LABEL[value.method].toLowerCase()} below.
        </div>
      )}

      {value.method === "form" ? (
        <FormMethodFields
          value={value}
          set={set}
          onChange={onChange}
          err={err}
          rootDomain={rootDomain}
          needSecret={needSecret}
          passwordHint={passwordHint}
        />
      ) : (
        <>
          <div className="hint" style={{ marginBottom: 8 }}>
            For logins a script can&apos;t get through (CAPTCHA, SSO, one-time codes). Log in to the site
            yourself in Chrome, press <b>F12</b> → <b>Network</b>, reload, click any request to{" "}
            <span className="mono">{rootDomain}</span>, and under <b>Request Headers</b> copy{" "}
            {value.method === "cookie" ? (
              <>the value of <span className="mono">Cookie</span></>
            ) : (
              <>the header that carries the login, usually <span className="mono">Authorization</span></>
            )}
            . Sessions expire: when Test login starts failing, paste a fresh one.
          </div>
          <div className="row">
            <div>
              <label>Page only a logged-in user can see *</label>
              <input
                value={value.loginUrl}
                placeholder={`https://${rootDomain}/dashboard`}
                aria-invalid={!!err("loginUrl")}
                onChange={(e) => set("loginUrl", e.target.value)}
              />
              <FieldError msg={err("loginUrl")} />
            </div>
          </div>
          <div className="row">
            {value.method === "header" && (
              <div style={{ maxWidth: 220 }}>
                <label>Header name *</label>
                <input
                  className="mono"
                  value={value.headerName}
                  onChange={(e) => set("headerName", e.target.value)}
                />
                <FieldError msg={err("headerName")} />
              </div>
            )}
            <div>
              <label>
                {SECRET_LABEL[value.method]} (stored encrypted){needSecret ? " *" : ""}
              </label>
              <textarea
                className="mono"
                rows={2}
                value={value.password}
                spellCheck={false}
                autoComplete="off"
                placeholder={
                  !needSecret && passwordHint
                    ? passwordHint
                    : value.method === "cookie"
                      ? "sessionid=abc123; csrftoken=…"
                      : "Bearer eyJhbGciOi…"
                }
                onChange={(e) => set("password", e.target.value)}
                style={{ width: "100%" }}
              />
              <FieldError msg={err("password")} />
            </div>
          </div>
          <div className="row">
            <SuccessCheck value={value} set={set} error={err("successValue")} />
          </div>
        </>
      )}
    </div>
  );
}

function FormMethodFields({
  value,
  set,
  onChange,
  err,
  rootDomain,
  needSecret,
  passwordHint,
}: {
  value: LoginForm;
  set: <K extends keyof LoginForm>(k: K, v: LoginForm[K]) => void;
  onChange: (next: LoginForm) => void;
  err: (k: keyof LoginForm) => string | undefined;
  rootDomain: string;
  needSecret: boolean;
  passwordHint?: string;
}) {
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
    <>
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
              <span className="mono">wait_for_url</span> (value). Success check kinds:{" "}
              <span className="mono">url_contains</span>, <span className="mono">url_not_contains</span>,{" "}
              <span className="mono">selector_visible</span>, <span className="mono">selector_hidden</span>.
              Use this for two-page logins (email → Next → password).
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
          <label>Password (stored encrypted){needSecret ? " *" : ""}</label>
          <input
            type="password"
            value={value.password}
            autoComplete="new-password"
            placeholder={needSecret ? undefined : passwordHint}
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
          <SuccessCheck value={value} set={set} error={err("successValue")} />
        </div>
      )}

      <div className="hint" style={{ marginTop: 6 }}>
        Finding selectors: open the login page in Chrome, right-click the field → <b>Inspect</b>, and
        use its id (<span className="mono">id=&quot;email&quot;</span> →{" "}
        <span className="mono">#email</span>) or name (
        <span className="mono">input[name=email]</span>). Behind a CAPTCHA, SSO or one-time code? Use{" "}
        <b>Pasted cookie</b> or <b>Pasted header</b> above instead.{" "}
        <button className="btn-sm" type="button" onClick={toggleAdvanced}>
          {value.advanced ? "Back to simple fields" : "Advanced: edit steps as JSON"}
        </button>
      </div>
    </>
  );
}
