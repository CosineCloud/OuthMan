# Log API integration and centralized collection

Use this contract to pull OuthMan logs into a centralized log viewer, and as the specification when exposing the same feature from other apps. This is a read-only **pull API**, not an endpoint for uploading logs. The external collector polls each app and stores/displays its responses.

## 1. Setup

1. Sign in to OuthMan as a configured administrator.
2. Under **Settings → IP allowlist**, allow the collector's directly connected IP/network. For local curl, allow `127.0.0.1`. Forwarded IP headers are ignored; behind a proxy, enforce original-client restrictions at the proxy.
3. Open **Settings → Log API** and enter a key name.
4. Choose an active app for **this app only**, or explicitly choose **All logs — centralized collector** for administrator-wide visibility.
5. Create the key and copy it immediately. Its plaintext is shown once; only its hash is retained. Keep it in the collector's backend secret store.

Log keys have `logs:read` permission only. They cannot create accounts, change settings, fetch backups, or use integration authentication. App secrets and backup-download keys are not log keys. An app-scoped key stops working when its app is revoked. A central key can still access retained history of revoked apps. Revoke any log key immediately using its **Revoke** button in Settings.

The UI's Access activity and API request log are independently scrollable (420px maximum height on desktop, 340px on small screens), with sticky column headers and keyboard-accessible scroll regions.

## 2. Working curl commands

These commands prompt for the actual key, so no JSON credential files, cookie jar, or key placeholder is needed.

Read account/access activity:

```sh
python3 -c 'import getpass; print("Authorization: Bearer " + getpass.getpass("Log API key: "))' \
  | curl --fail-with-body -H @- \
      'http://127.0.0.1:10070/api/logs?stream=activity&after=0&limit=100'
```

Read API requests:

```sh
python3 -c 'import getpass; print("Authorization: Bearer " + getpass.getpass("Log API key: "))' \
  | curl --fail-with-body -H @- \
      'http://127.0.0.1:10070/api/logs?stream=requests&after=0&limit=100'
```

Quote the URL so the shell does not interpret `&`. Use HTTPS beyond localhost. Never put a key in the query string, frontend bundle, analytics, or logs.

## 3. Endpoint and query fields

`GET /api/logs` requires `Authorization: Bearer <log_api_key>` and an allowed caller IP. No browser cookie is required. Responses are JSON with `Cache-Control: no-store`. CORS access from arbitrary browser origins is not provided; collect from a trusted backend.

| Query | Default | Meaning |
| --- | --- | --- |
| `stream` | `activity` | `activity` or `requests`; use a separate cursor for each |
| `after` | `0` | Return IDs strictly greater than this non-negative integer |
| `limit` | `100` | Page size, from 1–500 |
| `epoch` | omitted initially | Pass back the epoch from the first response on subsequent polls |

Entries are ordered by increasing ID. The key determines the app filter on the server: a caller cannot select another app with a query parameter. Unknown or repeated query parameters return 400.

Example response shape (illustrative IDs/timestamps):

```json
{
  "source": "outhman",
  "stream": "activity",
  "epoch": "f5f43e0f32d841cda0d19e4bd88e49e2",
  "entries": [
    {
      "id": 84,
      "created_at": 1794103200.0,
      "action": "Confirmed app login for example-app-id",
      "username": "person@example.com",
      "ip": "127.0.0.1",
      "browser": "MyAppBackend/1.0",
      "app_id": "example-app-id",
      "source": "outhman",
      "stream": "activity"
    }
  ],
  "next_after": 84,
  "has_more": false,
  "oldest_available_id": 1,
  "retention_gap": false
}
```

`created_at` is Unix epoch seconds (UTC); convert to the viewer's timezone for display. IDs are ordered within each stream and are not global across apps/instances. `source` identifies the product, not a unique deployment: the collector must assign a distinct `source_instance` to each configured origin.

Activity entry fields: `id`, `created_at`, `action`, `username`, `ip`, `browser`, `app_id`, `source`, `stream`.

Request entry fields: `id`, `created_at`, `method`, `endpoint`, `ip`, `client`, `status`, `app_id`, `source`, `stream`.

Passwords, access codes, authentication PINs, request bodies, response secrets, Authorization headers, and URL query strings are not exported. User-Agent/browser values are self-reported and usernames may contain personal data. Escape all text when rendering HTML and restrict central-viewer access to the intended administrators.

## 4. App scope and attribution

App-scoped keys return only integration activity and API requests attributed to that authenticated app. They do not receive account-wide browser activity, other apps' entries, backups, or administrative logs.

App attribution is attached only after the integration app credentials are verified. Rejected requests with bad/missing app credentials, ACL denials, older records predating this feature, browser actions, and administrative actions have `app_id: null` and are visible only to an all-logs key. A request with valid app credentials but failed user verification can still be attributed to that app. Supplying another app's ID with a bad secret cannot make a record appear in its private feed.

App IDs, event names, and usernames in example data are illustrative. Every app exposing this contract must establish attribution from its own verified security context, never from an arbitrary client-supplied app ID.

## 5. Incremental collector algorithm

Maintain a checkpoint for each `(source_instance, credential_scope, stream)` with `{epoch, after}`. Scope changes should start a new checkpoint so previously filtered history is not silently skipped.

```text
poll(source_instance, scope, stream):
    checkpoint = load_checkpoint(source_instance, scope, stream)
    response = GET /api/logs(
        stream=stream,
        after=checkpoint.after or 0,
        epoch=checkpoint.epoch if present,
        limit=500)
    require a successful, valid JSON response
    if retention_gap:
        surface a missing-history warning to the operator
    transaction in collector storage:
        upsert every entry using unique key
            (source_instance, response.epoch, stream, entry.id)
        save checkpoint(epoch=response.epoch, after=response.next_after)
    if has_more:
        fetch the next page immediately
    else:
        wait 10–30 seconds before polling again
```

Always save the returned `next_after`, even when `entries` is empty. For scoped feeds, it can advance over other apps' IDs. Never derive a cursor from timestamps: equal timestamps are possible and IDs do not have to be contiguous.

Only checkpoint **after** durable storage succeeds. On a timeout or failed write, retry the same cursor; upserting by the unique key prevents duplicates. Validate fields, ID ordering, and origin before ingestion. Use TLS validation, bounded HTTP timeouts, response-size limits, and exponential backoff with jitter for transient failures. Do not send Authorization across unexpected redirects.

### Restore and retention

The database has a persistent random `epoch`. Restoring an OuthMan backup rotates it atomically with the restored data. A request with an old epoch or `after` beyond the current high-water mark returns:

```json
{
  "error": "Log cursor expired or the database was restored. Start this stream from after=0 with the new epoch.",
  "epoch": "NEW_EPOCH",
  "stream": "activity",
  "reset_required": true,
  "next_after": 0
}
```

This uses HTTP 409. Record the reset, then begin at `after=0` with the new epoch. Store the new generation separately; restored events may repeat older content under a new epoch. Administrative replacement of the DB outside the restore API should also rotate the epoch; the app cannot detect every out-of-band copy.

The API request stream retains the latest 10,000 requests; the UI shows the latest 200. Activity records currently have no automatic pruning, while the UI shows the latest 200. The export API can page through all currently retained records. `oldest_available_id` describes the stream's global oldest retained ID; it may belong to a different app. `retention_gap` warns when a nonzero cursor predates retained history. It cannot recover deleted records, and starting with `after=0` does not imply complete historical coverage. Poll frequently enough to stay within retention.

The API does not record its own read polls as API-request entries, avoiding a self-generating collection loop. Key creation/revocation is recorded in administrative activity.

## 6. Status and error handling

| Status | Meaning / collector action |
| --- | --- |
| 200 | Validate and durably ingest, then advance the cursor |
| 400 | Invalid stream/query/cursor/page size; fix the request |
| 401 | Missing, invalid, or revoked log key; stop and alert the operator |
| 403 | Caller IP denied, app revoked, or privileged endpoint accessed without an admin session |
| 409 | Epoch/cursor reset; start at zero with returned epoch |
| 5xx / network error | Keep the checkpoint, back off, and retry |

A failed response must not be interpreted as an empty successful page.

## 7. Key management API

These operations require a configured administrator **cookie session**, not a log key. Use Settings for the simplest workflow. The existing same-origin JSON protections apply to POSTs.

| Route | Request / response |
| --- | --- |
| GET `/api/logs/keys` | Redacted `{keys:[{id,name,app_id,scope,created_at}]}` |
| POST `/api/logs/keys` | `{name,app_id}` → 201 `{id,api_key}`; `app_id:"*"` explicitly grants all logs |
| POST `/api/logs/keys/revoke` | `{id}` → `{ok:true}` |

Up to 100 configured keys are supported. Secrets use an `olk_` prefix plus 256 bits of random entropy; hashes are compared securely. Log key configuration is encrypted in the local control sidecar shared with backup scheduling, under a private machine key. It is not returned by the backup-control API or stored in downloadable database backups. A DB restore preserves issued/revoked log keys, but rotates the log epoch.

## 8. Apply the same feature to another app

Reference implementation: `log_export.py`, log routes/attribution in `server.py`, log epoch migration/restore handling in `backups.py`, Settings UI in `public/app.js`, and `test_log_api.py`.

To follow the same contract:

1. Assign a stable increasing ID to each entry within each stream and retain a stable random epoch for that database generation. Rotate the epoch during restore/reset. Reuse the response envelope and query names above.
2. Define explicit structured entry fields rather than exporting raw request/response dumps. Redact credentials and secret values at write time. Include a stable app/product identifier; configure instance identity in the collector.
3. Implement high-entropy read-only keys with server-side app/tenant scopes, one-time display, hashed storage, key names, immediate revocation, and separate admin-only key management. Authenticate and check IP/tenant scope on every request.
4. Query `id > after`, filter by the key's trusted app scope, order ascending, fetch `limit+1`, and return a safe `next_after` plus `has_more`. Bound the page size and index `(app_id,id)` for app-filtered reads. Read pagination bounds and rows consistently.
5. Document retention and report gaps rather than pretending missing history is complete. Keep a separate cursor per stream, origin, and scope. Do not log every export poll back into the exported request stream.
6. Give the collector a source configuration containing origin, product/source identifier, instance ID, streams, polling interval, and its scoped backend secret. Store entries with `(instance,epoch,stream,id)` uniqueness and update checkpoints in the same storage transaction.
7. Make the central viewer escape all values, show source/app/time/status, support filtering, and restrict logs containing personal data. Keep local long tables in capped-height, keyboard-accessible scroll regions.
8. Test app isolation, invalid/revoked keys, denied IPs, admin-only key management, read-only restrictions, pagination without duplicates, empty filtered pages, malformed queries, retention gaps, and restore/reset epochs with isolated temporary data.

For another database engine, replace the SQLite query/transaction adapter rather than copying it verbatim. For multi-process deployments, use shared configuration/key storage and consistent DB snapshots. Polling is authorized only for configured sources; this feature does not automatically discover or send logs to third parties.
