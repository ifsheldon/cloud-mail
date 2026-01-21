# Cloud Mail Audit Report

Date: 2026-01-21

Scope
- Reviewed source code in `mail-worker/` (Cloudflare Worker backend) and `mail-vue/` (Vue frontend).
- Did **not** audit minified third‑party assets under `mail-vue/public/tinymce/**` or image assets.
- No dynamic testing performed.

Summary
- No obvious backdoors found.
- Several **critical** and **high** vulnerabilities exist.
- **NEW**: Found a critical Privilege Escalation / IDOR vulnerability where any logged-in user can view or delete all system emails.

Findings (ordered by severity)

## Critical

### 1) Privilege Escalation / IDOR on Admin Endpoints (NEW)
- Impact: Any logged-in user (even non-admins) can view the latest system-wide emails and mass-delete emails belonging to other users.
- Locations:
  - `mail-worker/src/security/security.js` (RBAC middleware configuration)
  - `mail-worker/src/api/all-email-api.js`
- Evidence:
  - The `requirePerms` list in `security.js` protects `/allEmail/list` and `/allEmail/delete`, but fails to include `/allEmail/latest` and `/allEmail/batchDelete`.
  - The middleware logic only checks permissions if the path starts with a string in `requirePerms`.
- Recommendation:
  - Add `/allEmail/latest` and `/allEmail/batchDelete` to the `requirePerms` list in `security.js`.

### 2) Stored XSS via unsanitized email HTML rendering
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

### 3) Unauthenticated Resend webhook endpoint
- Impact: anyone can POST to `/webhooks` and update email status; potential integrity issues and abuse.
- Locations:
  - `mail-worker/src/api/resend-api.js`
  - `mail-worker/src/service/resend-service.js`
- Evidence:
  - No signature verification or shared secret check.
- Recommendation:
  - Verify Resend webhook signatures (HMAC/secret or signed header) and reject unsigned requests.

### 4) Weak password hashing
- Impact: stored passwords are hashed with salted SHA‑256 which is fast and vulnerable to offline cracking.
- Location:
  - `mail-worker/src/utils/crypto-utils.js`
- Recommendation:
  - Use a slow password hash (PBKDF2/argon2/bcrypt). Cloudflare Workers supports PBKDF2 via WebCrypto.

## Medium

### 5) Logout token revocation bug (async misuse)
- Impact: logout fails to remove the token, leaving it valid until expiration.
- Locations:
  - `mail-worker/src/security/user-context.js`
  - `mail-worker/src/service/login-service.js`
- Evidence:
  - `JwtUtils.verifyToken` is async but called without `await` in `userContext.getToken`, causing it to return `undefined` (via destructuring a Promise).
  - `loginService.logout` calls `userContext.getToken` without `await`, so `token` is a Promise, which never matches the string token in the array.
- Recommendation:
  - Add `await` to `JwtUtils.verifyToken` call in `userContext.getToken`.
  - Add `await` to `userContext.getToken` call in `loginService.logout`.

### 6) Password length check bug in reset flow
- Impact: weak/empty passwords can slip through due to incorrect comparison.
- Location:
  - `mail-worker/src/service/user-service.js`
- Evidence:
  - `if (password < 6)` compares string to number.
- Recommendation:
  - Use `if (!password || password.length < 6)`.

### 7) SQL injection risk in public bulk user add
- Impact: raw SQL with interpolated user input can lead to injection if the public token is compromised or if input validation is bypassed.
- Location:
  - `mail-worker/src/service/public-service.js`
- Recommendation:
  - Use parameterized queries (D1 `bind` or Drizzle).

### 8) Telegram email view tokens never expire
- Impact: leaked token URLs provide indefinite access to email contents.
- Location:
  - `mail-worker/src/service/telegram-service.js`
  - `mail-worker/src/utils/jwt-utils.js`
- Evidence:
  - `generateToken` is called without expiration parameter; `jwt-utils` treats this as no expiry (`exp` undefined).
- Recommendation:
  - Pass a short expiration time (e.g., 1 hour) to `generateToken`.

## Low/Medium

### 9) `/init/:secret` uses JWT secret in URL
- Impact: secrets in URLs can leak via logs, referrers, and proxies.
- Location:
  - `mail-worker/src/init/init.js`
- Evidence:
  - It compares the URL param `secret` directly with `c.env.jwt_secret`.
- Recommendation:
  - Use a separate init secret and POST it in the body, or require admin auth.

### 10) Public object access via `/oss/*`
- Impact: attachments are publicly accessible if keys are guessed or leaked.
- Location:
  - `mail-worker/src/api/r2-api.js`
- Recommendation:
  - Require auth or use signed URLs for sensitive attachments.

Additional Observations
- CORS is wide open (`*`) in `mail-worker/src/hono/hono.js`. This is not inherently unsafe given header-based auth, but increases risk if XSS is present.
- No rate limiting / lockout is implemented for login endpoints.

Suggested Next Steps
1) **IMMEDIATE**: Fix the RBAC configuration in `security.js` to protect `/allEmail/latest` and `/allEmail/batchDelete`.
2) Fix the stored XSS path (sanitize HTML + consider sandboxed rendering).
3) Add webhook signature verification for Resend.
4) Patch logout/token handling and password length validation.
5) Migrate password hashing to a slow KDF.