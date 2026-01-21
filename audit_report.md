# Cloud Mail Audit Report

Date: 2026-01-21

Scope
- Reviewed source code in `mail-worker/` (Cloudflare Worker backend) and `mail-vue/` (Vue frontend).
- Did **not** audit minified third‑party assets under `mail-vue/public/tinymce/**` or image assets.
- No dynamic testing performed.

Summary
- No obvious backdoors found.
- Several **high/critical** vulnerabilities exist that should be addressed before deployment, especially around HTML rendering and webhook authentication.

Findings (ordered by severity)

## Critical

### 1) Stored XSS via unsanitized email HTML rendering
- Impact: attacker can execute arbitrary JS in users’ browsers by sending crafted email HTML; can steal tokens stored in `localStorage`, perform actions as the victim, etc.
- Locations:
  - `mail-vue/src/components/shadow-html/index.vue` (uses `innerHTML` with untrusted HTML)
  - `mail-vue/src/views/content/index.vue` (renders `email.content` via `ShadowHtml`)
  - `mail-worker/src/template/email-html.js` (server-side template embeds untrusted HTML into shadow DOM)
- Evidence:
  - `shadowRoot.innerHTML = ... ${cleanedHtml}` without robust sanitization.
- Recommendation:
  - Sanitize HTML on both server and client using a strict allowlist (e.g., DOMPurify with locked-down config), stripping event handlers, `javascript:` URLs, iframes, etc.
  - Consider rendering untrusted HTML in a sandboxed iframe with a restrictive CSP.

## High

### 2) Unauthenticated Resend webhook endpoint
- Impact: anyone can POST to `/webhooks` and update email status; potential integrity issues and abuse.
- Locations:
  - `mail-worker/src/api/resend-api.js`
  - `mail-worker/src/service/resend-service.js`
- Evidence:
  - No signature verification or shared secret check.
- Recommendation:
  - Verify Resend webhook signatures (HMAC/secret or signed header) and reject unsigned requests.

### 3) Weak password hashing
- Impact: stored passwords are hashed with salted SHA‑256 which is fast and vulnerable to offline cracking.
- Location:
  - `mail-worker/src/utils/crypto-utils.js`
- Recommendation:
  - Use a slow password hash (PBKDF2/argon2/bcrypt). Cloudflare Workers supports PBKDF2 via WebCrypto.

## Medium

### 4) Logout token revocation bug (async misuse)
- Impact: logout may remove the wrong token, leaving the current token valid.
- Locations:
  - `mail-worker/src/security/user-context.js`
  - `mail-worker/src/service/login-service.js`
- Evidence:
  - `JwtUtils.verifyToken` is async but called without `await` in `getToken`, returning undefined token.
- Recommendation:
  - `await JwtUtils.verifyToken(...)`, handle null, and revoke the exact token used.

### 5) Password length check bug in reset flow
- Impact: weak/empty passwords can slip through due to incorrect comparison.
- Location:
  - `mail-worker/src/service/user-service.js`
- Evidence:
  - `if (password < 6)` compares string to number.
- Recommendation:
  - Use `if (!password || password.length < 6)`.

### 6) SQL injection risk in public bulk user add
- Impact: raw SQL with interpolated user input can lead to injection if the public token is compromised.
- Location:
  - `mail-worker/src/service/public-service.js`
- Recommendation:
  - Use parameterized queries or Drizzle inserts.

### 7) Telegram email view tokens never expire
- Impact: leaked token URLs provide indefinite access to email contents.
- Location:
  - `mail-worker/src/service/telegram-service.js`
- Recommendation:
  - Add `exp` to JWTs and/or one‑time tokens stored in KV. Avoid long‑lived URL tokens.

## Low/Medium

### 8) `/init/:secret` uses JWT secret in URL
- Impact: secrets in URLs can leak via logs, referrers, and proxies.
- Location:
  - `mail-worker/src/init/init.js`
- Recommendation:
  - Use a separate init secret and POST it in the body or require admin auth.

### 9) Public object access via `/oss/*`
- Impact: attachments are publicly accessible if keys are guessed or leaked.
- Location:
  - `mail-worker/src/api/r2-api.js`
- Recommendation:
  - Require auth or use signed URLs for sensitive attachments.

Additional Observations
- CORS is wide open (`*`) in `mail-worker/src/hono/hono.js`. This is not inherently unsafe given header-based auth, but increases risk if XSS is present.
- No rate limiting / lockout is implemented for login endpoints. Consider adding basic throttling or Turnstile on repeated failures.

Suggested Next Steps
1) Fix the stored XSS path first (sanitize HTML + consider sandboxed rendering).
2) Add webhook signature verification for Resend.
3) Migrate password hashing to a slow KDF (PBKDF2/argon2/bcrypt).
4) Patch logout/token handling and password length validation.
5) Replace raw SQL in `public-service` with parameterized inserts.

