# OuthMan

Run on an ARM64/ARMv7 Raspberry Pi or x86-64 Docker host using [Deployment_inctructions.MD](Deployment_inctructions.MD). The Docker image runs as a non-root user and stores accounts, keys, and backups in a persistent volume.

A local authentication manager for Cosine Apps. Uses Python 3.11+ and SQLite, plus the cryptography package for encrypted backups.

## Run

```sh
python3 -m pip install -r requirements.txt
python3 server.py
```

Open http://127.0.0.1:10070. Initial admin: `admin@admin.com` / `pass123`. On first login, both credentials must change before any other action. Passwords must be at least 8 characters. Account and audit data persist in `data/outhman.sqlite3`; keep this directory private and back it up appropriately.

Admin creates a 64-bit random invitation displayed once as 16 hexadecimal characters. Invitations support 30 seconds, 1 minute, 10 minutes, or a custom future date. They are stored hashed and their secret is erased on redemption. Redemption, account creation, and invitation consumption occur in one database transaction. The admin portal records the user, time, directly connected IP, and browser User-Agent (self-reported by the browser).

Users register with an invitation and choose credentials for use across Cosine Apps; these need not match personal accounts. Returning users sign in with those credentials. Generate code creates a cryptographically random six-digit code valid for 60 seconds. The newest code replaces the previous code. Expiry never automatically generates a replacement.

The default port is 10070. Ports below 1024, including 1007, may require elevated privileges on macOS.

## Verification

```sh
python3 -m unittest -v
```

Tests use a temporary database and localhost server, covering admin setup enforcement, invitation replay and expiry, access restrictions, code expiry, audit records, logout, and returning-user login.

## Deployment and integration

This implementation runs locally; it has not been deployed. Before exposing it publicly, serve behind HTTPS with `OUTHMAN_SECURE_COOKIE=1`, replace the bootstrap credentials immediately, and use a production application server. Set `HOST`, `PORT`, or `OUTHMAN_DB` to override defaults. Sessions expire after eight hours; failed login/invitation attempts are limited to ten per IP per fifteen minutes. Forwarded IP headers are deliberately ignored; behind a proxy, the recorded IP will be the proxy's address unless a trusted-proxy configuration is implemented.

## REST integration for XYZ / Cosine Apps

See [the complete app integration guide](INTEGRATION.md) for the protocol, curl examples, storage requirements, failure handling, and implementation checklist.

The admin portal contains app provisioning, revocation, the full protocol, and curl examples using the current OuthMan origin. Restart the server after updating; new tables are added automatically without replacing existing accounts.

1. Admin creates an app credential. Set the returned `app_id` and once-visible 128-bit `app_secret` in XYZ's backend environment. Never ship these in frontend code.
2. At XYZ registration, collect the user's existing OuthMan username/email, matching password, and a freshly generated six-digit code. XYZ backend sends `POST /api/v1/enroll`. Successful enrollment consumes the code and returns a once-visible 128-bit `user_key`, plus immutable `user_id`. Store the key encrypted against the local account ID. Keep only a password hash for local password checks.
3. At XYZ login, validate the local credentials, collect a fresh OuthMan code, and create a unique random `request_id` bound to the pending browser login session. XYZ backend sends username, password, code, stored user key and request ID to `POST /api/v1/verify`.
4. Success consumes the code atomically and returns `auth_pin` (a random 128-bit authentication PIN), `expires_at`, and `request_id`. The PIN expires after 30 seconds.
5. XYZ backend sends `POST /api/v1/confirm` with username, PIN and the same request ID. Only grant the pending login after checking `verified: true`, app ID, stored immutable user ID and request ID. Confirmation consumes the PIN atomically. The PIN never needs to reach the browser.

Every endpoint requires `Content-Type: application/json`, `X-OuthMan-App: <app_id>` and `Authorization: Bearer <app_secret>`. No cookies or browser session are required. All calls must originate from the integrating backend. Use HTTPS beyond localhost. These endpoints do not generate codes for apps: the user generates the code in OuthMan.

Request bodies:

```json
{"username":"person@example.com","password":"USER_PASSWORD","code":"012345"}
```

```json
{"username":"person@example.com","password":"USER_PASSWORD","code":"654321","user_key":"STORED_128_BIT_KEY","request_id":"FRESH_RANDOM_LOGIN_REQUEST_ID"}
```

```json
{"username":"person@example.com","auth_pin":"PIN_FROM_VERIFY","request_id":"SAME_LOGIN_REQUEST_ID"}
```

Example enrollment from the XYZ backend (replace placeholders; use a JSON serializer for real user input):

```sh
curl --fail-with-body http://127.0.0.1:10070/api/v1/enroll \
  -H 'Content-Type: application/json' \
  -H 'X-OuthMan-App: YOUR_APP_ID' \
  -H 'Authorization: Bearer YOUR_APP_SECRET' \
  --data '{"username":"person@example.com","password":"USER_PASSWORD","code":"012345"}'
```

Responses: enrollment `201 {app_id,user_id,username,user_key}`; verification `200 {auth_pin,expires_at,request_id}`; confirmation `200 {verified:true,app_id,user_id,username,request_id}`. Errors: 400 malformed input; 401 invalid credentials, code, PIN, or expired/consumed credential; 409 account already linked; 429 ten failed requests per account or caller IP within fifteen minutes. Fail closed on all errors and timeouts. If a success response is lost after code/PIN consumption, start over with a fresh code. Do not log request bodies or response secrets. Re-enrollment cannot retrieve an existing key; loss requires administrator/database recovery, not automatic replacement.

OuthMan stores app secrets, per-user keys and pending PINs as SHA-256 hashes; the XYZ backend must retain its own encrypted per-user keys. App revocation immediately blocks its endpoints and deletes pending PINs. IP/browser values in integration audit entries describe the calling backend, not the end user. Existing browser access codes are now consumed by successful app enrollment or verification, across all apps.

## Groups and code limits

Administrators manage **Groups & account limits** in the dashboard. Create or edit a group, select users and allowed apps, then save. A user must share a group with an app to enroll, verify, or confirm authentication. New users and apps start without group access. On upgrade, existing users and apps are placed in “Existing access” to preserve their access; edit that group to restrict it. Group changes invalidate pending authentication PINs.

Set a maximum code count per non-admin account (blank means unlimited). Counts run since the last admin release, with no automatic reset. After the allowed number of generated codes, the next generation request invalidates the current code and PINs and blocks the account for five minutes. It then remains suspended until an administrator selects **Release & reset count** and saves. Blocking applies to browser login, code generation, and app authentication, including existing browser sessions. Administrators are exempt to preserve account recovery.

In Access activity, browser/device information stays on one line; click it to expand the complete value.

## Integration IP ACL

Before calling `/api/v1/enroll`, `/api/v1/verify`, or `/api/v1/confirm`, an admin must configure **API IP allowlist (ACL)** in the dashboard. Enter backend IPv4/IPv6 addresses or CIDR networks, one per line. The default empty list denies all integration requests (403), including localhost. Add `127.0.0.1` for local curl calls. This applies to every API client, regardless of User-Agent. App credentials and group authorization are still required. Browser administration is unaffected.

The ACL uses the directly connected peer IP and ignores forwarded headers. Behind a reverse proxy it sees the proxy IP; configure original-client restrictions at that proxy. Saving the ACL invalidates pending PINs; restart authentication with a fresh code.

## API request log

The admin dashboard shows the latest 200 integration requests, including ACL denials, authentication failures, malformed requests, and successful calls. It records time, method, endpoint, directly connected IP, HTTP status, and client User-Agent (self-reported). The database retains the latest 10,000 entries. Click Refresh to load new entries. Bodies, query strings, Authorization headers, and response payloads are not recorded. Logging starts after this update; earlier requests cannot be recovered.

## Settings, themes, and backup

Use **Settings** to manage administrative controls and appearance. Light and dark modes are available; appearance preferences are saved in the current browser. The light palette uses cool-gray canvas, white cards, electric blue actions, mint success indicators, and amber pending states.

**Backup & restore** creates encrypted `.outhman` files using a passphrase of at least 12 characters. Backups can be downloaded in the UI or with an admin-authenticated curl call; backup access also requires an allowed caller IP. Restore replaces the database records, invalidates all OuthMan sessions/codes/PINs, and preserves an encrypted pre-restore recovery copy. Keep the passphrase safely; there is no recovery if it is lost. See [the backup feature guide](backup_feature.md) for commands, limits, and included records.

Backup scheduling and CSO transfer are handled externally by `backMan_runner.py` and `backMan.py`. The host shows file sizes/timestamps and issues 128-bit trigger/download keys in **Settings → Backup & restore**. The old host timer is no longer started. See [backup_feature.md](backup_feature.md) for setup, retry/checksum behavior, curl, and CSO integration.

## Account approval and browser binding

Invitation registration creates a pending account and consumes the invitation, but does not sign the user in. Under **Settings → Users & access**, administrators approve pending accounts. Their first successful login after approval binds the account to that browser profile using a private HttpOnly device cookie plus a fingerprint of browser family, platform, and touch capability. Every browser session request checks both. Login attempts from another profile/browser, including copied session cookies without the device proof, receive the same `Incorrect username or password.` response as invalid credentials.

**Release binding** clears the stored binding, browser sessions, codes, and pending authentication PINs. The next approved login with valid credentials binds the account again. It does not release a code-limit suspension or change group access. Existing accounts stay approved on upgrade and bind at their next login; existing non-admin sessions must sign in again. Administrators are exempt so account recovery remains available.

This is browser-profile binding, not hardware attestation. Private browsing, another profile, clearing cookies, or expiry of the one-year device cookie requires admin release. Browser versions are excluded from the fingerprint to avoid blocking routine updates. Copying the device cookie together with matching browser attributes can bypass this check; fingerprints alone are not a strong identity. Use HTTPS beyond localhost; the browser fingerprint uses Web Crypto and requires a secure context. Integrating apps still control their own sessions and devices.

## Three-attempt login block

Non-admin accounts are blocked after three consecutive failed browser logins, including incorrect passwords and failed browser/device checks. The first failure shows two attempts remaining; the second shows one; the third blocks the account until an administrator uses **Settings → Users & access → Release login block**. A successful login before the limit resets the count. Counts persist across browser changes, IP changes, and server restarts. Blocking invalidates existing OuthMan sessions, codes, and pending PINs, and prevents app authentication. Device failures retain generic login wording without mentioning the binding.

Releasing a login block resets the failure counter but does not release the browser binding, grant approval/group access, or lift a code-generation suspension. There is no automatic timeout for this block. Administrators are exempt so they can recover user accounts; the existing IP failure throttle still applies.

## Compact account actions, suspension, and deletion

**Settings → Users & access** groups compact Approve, Release login block, Release binding, Suspend/Resume, and Delete buttons in the Action column. Suspend immediately invalidates browser sessions, codes, and PINs and blocks browser and integration authentication until an admin clicks Resume. Resume preserves browser binding, approval, groups, and any separate login/code-limit block.

Delete requires confirmation and removes credentials, device binding, group membership, app links, and active access. An anonymous ID tombstone prevents immutable user IDs from being reused. Existing audit history, used invitations, and encrypted backups are retained; restoring an earlier backup can restore the previous account. Administrator accounts cannot be suspended or deleted through these controls.

## Scrollable logs and centralized log export

Access activity and API request log now scroll within capped-height panels with sticky headers. Under **Settings → Log API**, administrators can issue/revoke read-only export keys for one app or all logs. Collectors use `GET /api/logs` with a Bearer log key and an allowed caller IP. See [LOG_API_INT.MD](LOG_API_INT.MD) for curl examples, stream fields, incremental collection, key scope, retention, and the contract other apps can implement.

## BackMan and CSO

Copy `backMan.example.json` to `backMan.config.json`, configure host/CSO URLs and secrets through the named environment variables, then run `python3 backMan_runner.py --config backMan.config.json --once` for one cycle or omit `--once` for scheduled operation. Each transfer is verified by a CSO read-back checksum. No cloud transfer is enabled automatically. The CSO API contract is in [Backup_API.md](Backup_API.md).
