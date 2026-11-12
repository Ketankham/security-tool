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
};

const CREDENTIAL_REF = "password";

export type LoginRecipe = {
  start_url: string;
  steps: Array<Record<string, string>>;
  success_assertion: { kind: SuccessKind; value: string };
};

export type BuiltLogin =
  | { ok: true; recipe: LoginRecipe; password: string | null }
  | { ok: false; error: string };

function simpleRecipe(f: LoginForm): LoginRecipe {
  const steps: Array<Record<string, string>> = [];
  if (f.usernameSelector.trim()) {
    steps.push({ action: "fill", selector: f.usernameSelector.trim(), value: f.username });
  }
  steps.push({
    action: "fill_secret",
    selector: f.passwordSelector.trim(),
    credential_ref: CREDENTIAL_REF,
  });
  steps.push({ action: "click", selector: f.submitSelector.trim() });
  return {
    start_url: f.loginUrl.trim(),
    steps,
    success_assertion: { kind: f.successKind, value: f.successValue.trim() },
  };
}

/**
 * Turns the form into an API payload, or a message saying what's missing.
 * `passwordRequired` is false when editing a persona that already has a
 * login: leaving the password blank then keeps the stored one.
 */
export function buildLogin(f: LoginForm, passwordRequired: boolean): BuiltLogin {
  const password = f.password ? f.password : null;
  const missingPassword: BuiltLogin = { ok: false, error: "Enter the password for this login." };

  if (f.advanced) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(f.json);
    } catch (e) {
      return { ok: false, error: `Recipe JSON is not valid JSON: ${(e as Error).message}` };
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return { ok: false, error: "Recipe JSON must be an object with start_url, steps and success_assertion." };
    }
    if (passwordRequired && !password) return missingPassword;
    // Shape is validated server-side (per-step required fields, exactly one
    // fill_secret); its error comes back readable via ApiError.
    return { ok: true, recipe: parsed as LoginRecipe, password };
  }

  if (!/^https?:\/\//i.test(f.loginUrl.trim())) {
    return { ok: false, error: "Login page URL must start with http:// or https://." };
  }
  if (f.usernameSelector.trim() && !f.username) {
    return { ok: false, error: "Enter the username to type into the username field (or clear that selector)." };
  }
  if (!f.usernameSelector.trim() && f.username) {
    return { ok: false, error: "Enter the username field's selector (e.g. #email), or clear the username." };
  }
  if (!f.passwordSelector.trim()) return { ok: false, error: "Enter the password field's selector (e.g. #password)." };
  if (passwordRequired && !password) return missingPassword;
  if (!f.submitSelector.trim()) return { ok: false, error: "Enter the submit button's selector." };
  if (!f.successValue.trim()) return { ok: false, error: "Say how to tell the login worked (e.g. URL contains /dashboard)." };
  return { ok: true, recipe: simpleRecipe(f), password };
}

function hostOf(url: string): string | null {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}

export function LoginRecipeFields({
  value,
  onChange,
  rootDomain,
  passwordHint,
}: {
  value: LoginForm;
  onChange: (next: LoginForm) => void;
  rootDomain: string;
  passwordHint?: string;
}) {
  const set = <K extends keyof LoginForm>(k: K, v: LoginForm[K]) => onChange({ ...value, [k]: v });

  const host = hostOf(value.loginUrl.trim());
  const root = rootDomain.toLowerCase();
  const offDomain = host !== null && host !== root && !host.endsWith(`.${root}`);

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
              <label>Login page URL</label>
              <input
                value={value.loginUrl}
                placeholder={`https://${rootDomain}/login`}
                onChange={(e) => set("loginUrl", e.target.value)}
              />
            </div>
          </div>
          {offDomain && (
            <div className="notice" style={{ marginTop: 6 }}>
              This login page is on <span className="mono">{host}</span>, not{" "}
              <span className="mono">{rootDomain}</span>. That&apos;s normal for SSO, but make sure the
              client has authorised testing that host too.
            </div>
          )}
          <div className="row">
            <div>
              <label>Username field (CSS selector)</label>
              <input
                className="mono"
                value={value.usernameSelector}
                placeholder="#email"
                onChange={(e) => set("usernameSelector", e.target.value)}
              />
            </div>
            <div>
              <label>Username</label>
              <input
                value={value.username}
                autoComplete="off"
                placeholder="member@client.com"
                onChange={(e) => set("username", e.target.value)}
              />
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

      <div className="row">
        {!value.advanced && (
          <div>
            <label>Password field (CSS selector)</label>
            <input
              className="mono"
              value={value.passwordSelector}
              placeholder="#password"
              onChange={(e) => set("passwordSelector", e.target.value)}
            />
          </div>
        )}
        <div>
          <label>Password (stored encrypted)</label>
          <input
            type="password"
            value={value.password}
            autoComplete="new-password"
            placeholder={passwordHint}
            onChange={(e) => set("password", e.target.value)}
          />
        </div>
      </div>

      {!value.advanced && (
        <div className="row">
          <div>
            <label>Submit button (CSS selector)</label>
            <input
              className="mono"
              value={value.submitSelector}
              onChange={(e) => set("submitSelector", e.target.value)}
            />
          </div>
          <div>
            <label>Login succeeded if</label>
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
